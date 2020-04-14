/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <set>

#include <E/E_TimerModule.hpp>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	virtual void timerCallback(void* payload) final;
public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	struct Address;
	struct AddressKey;
	struct AddrInfo;
	struct ListenController;
	struct AcceptController;
	struct AzocketKey;
	struct Azocket;
	struct AddressHash;
	struct AddressKeyHash;
	struct AzocketKeyHash;

	enum AzocketState : uint8_t {
		STATE_CLOSED,
		STATE_LISTEN,
		STATE_SYNSENT,
		STATE_SYN_RCVD,
		STATE_ESTAB
	};

	enum PacketFlag : uint8_t {
		FLAG_FIN,
		FLAG_SYN,
		FLAG_RST,
		FLAG_PSH,
		FLAG_ACK,
		FLAG_URG,
		FLAG_ECE,
		FLAG_CWR
	};

	enum PacketType : uint8_t {
		FIN = (1 << PacketFlag::FLAG_FIN), // 1
		SYN = (1 << PacketFlag::FLAG_SYN), // 2
		ACK = (1 << PacketFlag::FLAG_ACK), // 16
		FINACK = (1 << PacketFlag::FLAG_FIN) | (1 << PacketFlag::FLAG_ACK), // 17
		SYNACK = (1 << PacketFlag::FLAG_SYN) | (1 << PacketFlag::FLAG_ACK)  // 18
	};

	struct Address {
		uint32_t ip;
		uint16_t port;

		Address() : ip(0), port(0) {}
		Address(uint32_t ip) : ip(ip) {
			std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
			port = std::uniform_int_distribution<uint16_t>(1025, UINT16_MAX)(rng);
		}
		Address(uint32_t ip, uint16_t port) : ip(ip), port(port) {}
		Address(uint16_t port, uint32_t ip) : ip(ip), port(port) {}
		Address(const AddrInfo &addrInfo) {
			sockaddr_in addr = *((sockaddr_in *) &addrInfo.addr);
			ip = ntohl(addr.sin_addr.s_addr);
			port = ntohs(addr.sin_port);
		}

		friend bool operator < (const Address &f, const Address &s) {
			return f.ip < s.ip || (f.ip == s.ip && f.port < s.port);
		}
		friend bool operator == (const Address &f, const Address &s) {
			return f.ip == s.ip && f.port == s.port;
		}

		void toNetwork() {
			ip = htonl(ip);
			port = htons(port);
		}

		void toHost() {
			// std::cout << "Before: " << ip << ", " << port << "\n";

			ip = ntohl(ip);
			port = ntohs(port);

			// std::cout << "After: " << ip << ", " << port << "\n";
		}

		friend std::ostream& operator << (std::ostream& stream, const Address &address) {
			std::string ip_str = "";
			uint32_t ip = address.ip;
			for (int i = 0; i < 4; i++) {
				ip_str = std::to_string(ip & 0xff) + "." + ip_str; 
				ip >>= 8;
			}
			ip_str.erase(ip_str.size() - 1U);
			stream << "ip: " << ip_str << ", port: " << address.port;
			return stream;
		}

		AddrInfo getAddrInfo() const {
			return AddrInfo(*this);
		}
	};

	struct AddressKey {
		Address source;
		Address dest;

		AddressKey() {}
		AddressKey(const Address &source) : source(source) {}
		AddressKey(const Address &source, const Address &dest) : source(source), dest(dest) {}

		friend const bool operator < (const AddressKey &f, const AddressKey &s) {
			return f.source < s.source || (f.source == s.source && f.dest < s.dest);
		}
		friend const bool operator == (const AddressKey &f, const AddressKey &s) {
			return f.source == s.source && f.dest == s.dest;
		}

		void toNetwork() {
			source.toNetwork();
			dest.toNetwork();
		}

		void toHost() {
			// std::cout << "Changing source...\n";
			source.toHost();

			// std::cout << "Changing dest...\n";
			dest.toHost();
		}
	};

	struct AddrInfo {
		sockaddr addr;
		socklen_t addrlen;

		AddrInfo() {}
		AddrInfo(sockaddr addr, socklen_t addrlen) : addr(addr), addrlen(addrlen) {}
		AddrInfo(const Address &address) {
			sockaddr_in addr_in;
			addr_in.sin_family = AF_INET;
			addr_in.sin_addr.s_addr = htonl(address.ip);
			addr_in.sin_port = htons(address.port);

			addr = *((sockaddr *) &addr_in);
			addrlen = sizeof(addr);
		}

		Address getAddress() const {
			return Address(*this);
		}
	};

	struct ListenController {
		int backlog;
		int parent_sockfd;
		std::vector<int> child_sockfds;

		ListenController() : backlog(0) {}
	};

	struct AcceptController {
		bool blocked;
		UUID syscall_id;
		sockaddr *addr;
		socklen_t *addrlen;

		AcceptController() : blocked(false) {}
	};

	struct AzocketKey {
		int sockfd;
		int pid;

		AzocketKey() : sockfd(-1), pid(-1) {}
		AzocketKey(int sockfd, int pid) : sockfd(sockfd), pid(pid) {}

		friend bool operator == (const AzocketKey &f, const AzocketKey &s) {
			return f.sockfd == s.sockfd && f.pid == s.pid;
		}
	};

	struct Azocket {
		AddressKey addressKey;

		AzocketKey key;
		UUID syscall_id;

		uint32_t seq_num;
		uint32_t ack_num;

		ListenController listenControl;
		AcceptController acceptControl;
		AzocketState state;

		Azocket() : state(STATE_CLOSED) {}
		Azocket(const AzocketKey &key, const AzocketState &state) : key(key), state(state) {
			std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
			seq_num = std::uniform_int_distribution<uint32_t>(0, UINT32_MAX)(rng);
		}
	};

	struct HashTemplates {
		template <class T>
		static inline void hash_combine(size_t &seed, const T &value) {
			std::hash<T> hasher;
			seed ^= hasher(value) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		}
	};

	struct AddressHash {
		static size_t hash(const Address &address) {
			size_t hash = 0;
			HashTemplates::hash_combine(hash, address.ip);
			HashTemplates::hash_combine(hash, address.port);
			return hash;
		}
		size_t operator () (const Address &address) const {
			return hash(address);
		}
	};

	struct AddressKeyHash {
		static size_t hash(const AddressKey &addressKey) {
			size_t hash_source = AddressHash::hash(addressKey.source);
			size_t hash_dest = AddressHash::hash(addressKey.dest);

			size_t hash = 0;
			HashTemplates::hash_combine(hash, hash_source);
			HashTemplates::hash_combine(hash, hash_dest);
			return hash;
		}
		size_t operator () (const AddressKey &addressKey) const {
			return hash(addressKey);
		}
	};

	struct AzocketKeyHash {
		static size_t hash(const AzocketKey &azocketKey) {
			size_t hash = 0;
			HashTemplates::hash_combine(hash, azocketKey.sockfd);
			HashTemplates::hash_combine(hash, azocketKey.pid);
			return hash;
		}
		size_t operator () (const AzocketKey &azocketKey) const {
			return hash(azocketKey);
		}
	};

	std::unordered_map<AddressKey, AzocketKey, AddressKeyHash> addressKeyToAzocketKey;
	std::unordered_map<AzocketKey, AddrInfo, AzocketKeyHash> azocketKeyToAddrInfo;
	std::unordered_map<Address, AzocketKey, AddressHash> listenAddressToAzocketKey;
	std::unordered_map<AzocketKey, Azocket, AzocketKeyHash> azocketKeyToAzocket;
	std::unordered_set<AzocketKey, AzocketKeyHash> azocketKeys;
	std::unordered_set<Address, AddressHash> bindedAddresses;

	virtual int _syscall_socket(int pid) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int type, int protocol) final;
	virtual void syscall_close(UUID syscallUUID, int pid, int sockfd) final;
	virtual int _syscall_bind(int sockfd, int pid, struct sockaddr *addr, socklen_t addrlen) final;
	virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) final;
	virtual void syscall_connect(UUID syscallUUID,  int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
	virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) final;
	virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) final;
	virtual void _syscall_getpeername(int sockfd, int pid, struct sockaddr *addr, socklen_t* addrlen) final;
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) final;
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;

	virtual void implicit_bind(int sockfd, int pid, uint32_t dest_ip) final;
	virtual Packet* makePacket(struct Azocket &azocket, PacketType type) final;
	virtual void dispatchPacket(struct Azocket &azocket, PacketType type) final;	
	virtual bool readPacket(Packet *packet, uint8_t &flags, AddressKey &address_key, uint32_t &seq_num, uint32_t &ack_num) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
