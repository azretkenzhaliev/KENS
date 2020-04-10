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

private:
	virtual void timerCallback(void* payload) final;
public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
		// fds is a hash table for the active file descriptors.
	std::unordered_set<int> fds;

	// sockfdToAddrInfo is a hash table, which contains
	// (socket descriptor, (port/ip info, length of info in bytes)).
	// It is the main data structure used for the effective
	// socket descriptor <-> port/ip translation.
	std::unordered_map<int, std::pair<struct sockaddr, socklen_t>> sockfdToAddrInfo;
	
	std::unordered_map<std::pair<uint32_t, uint16_t>, int> IPPortToSockfd;

	// binded is a hash table, which stores the active port/ip bindings.
	// It is the main data structure used for binding collision checking.
	std::unordered_set<std::pair<uint16_t, uint32_t>> binded;
		
	enum AzocketState : uint8_t {
		STATE_CLOSED,
		STATE_LISTEN,
		STATE_SYNSENT,
		STATE_SYN_RCVD,
		STATE_ESTAB
	};

	struct Azocket {
		uint32_t source_ip;
		uint16_t source_port;
		uint32_t dest_ip;
		uint16_t dest_port;

		int pid;
		int sockfd;

		uint32_t seq_num;
		uint32_t ack_num;

		UUID syscall_id;

		int backlog;

		AzocketState state;
	};

	// map: int (sockfd) -> Azocket
	std::unordered_map<int, struct Azocket> sockfdToAzocket;

	struct SipDip {
		uint32_t source_ip;
		uint16_t source_port;
		uint32_t dest_ip;
		uint16_t dest_port;

		SipDip() {
			source_ip = source_port = 0;
			dest_ip = dest_port = 0;
		}
		SipDip(uint32_t _source_ip, uint16_t _source_port, uint32_t _dest_ip, uint16_t _dest_port) {
			source_ip = _source_ip;
			source_port = _source_port;
			dest_ip = _dest_ip;
			dest_port = _dest_port;
		}

		friend const bool operator < (SipDip f, SipDip s) {
			return f.source_ip < s.source_ip || (f.source_ip == s.source_ip && f.source_port < s.source_port);
		}
	};
	
	// map: SipDip -> sockfd
	std::map<struct SipDip, int> SipDipToSockfd;

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
		FIN = (1 << PacketFlag::FLAG_FIN),
		SYN = (1 << PacketFlag::FLAG_SYN),
		SYNACK = (1 << PacketFlag::FLAG_SYN) | (1 << PacketFlag::FLAG_ACK),
		ACK = (1 << PacketFlag::FLAG_ACK)
	};

	virtual int _syscall_socket(UUID syscallUUID, int pid, int type, int protocol) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int type, int protocol) final;
	virtual void syscall_close(UUID syscallUUID, int pid, int sockfd) final;
	virtual int _syscall_bind(int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
	virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) final;
	virtual void syscall_connect(UUID syscallUUID,  int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) final;
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;

	virtual void implicit_bind(int sockfd, uint32_t dest_ip) final;
	virtual uint8_t getFlags(Packet *packet) final;
	virtual Packet* makePacket(struct Azocket &azocket, PacketType type) final;
	virtual void sendSYNPacket(struct Azocket &azocket) final;	
	virtual void sendSYNACKPacket(struct Azocket &azocket) final;
	virtual void sendACKPacket(struct Azocket &azocket) final;
	virtual SipDip getSipDip(uint32_t source_ip, uint16_t source_port, uint32_t dest_ip, uint16_t dest_port) final;
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
