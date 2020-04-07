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

	// binded is a hash table, which stores the active port/ip bindings.
	// It is the main data structure used for binding collision checking.
	std::unordered_set<std::pair<uint16_t, uint32_t>> binded;
		
	typedef enum { 
		STATE_CLOSED,
		STATE_LISTEN, 
		STATE_SYNSENT, 
		STATE_SYN_RCVD,
		STATE_ESTAB
	} sockstate;

	// Azocket:
	// - source ip
	// - source port
	// - dest ip
	// - dest port
	// - sockfd
	// - seq num
	// - syscall ID (UUID)
	// - backlog
	// - state
	struct Azocket {
		uint32_t source_ip;
		uint16_t source_port;
		uint32_t dest_ip;
		uint16_t dest_port;
		int sockfd;
		uint32_t seq_num;
		UUID syscall_id;
		int backlog;
		sockstate state;

		void sendSYNPacket(TCPAssignment *context){
			// 12 - Ethernet header
			// 20 - IP header structure

			Packet *packet = context->allocatePacket(34);
			packet->writeData(14+12, (void *) source_ip, 4);
			packet->writeData(14+16, (void *) dest_ip, 4);
			packet->writeData(14+20+0, (void *) source_port, 2);
			packet->writeData(14+20+2, (void *) dest_port, 2);
			int flag = 
			packet->writeData(14+20+13, 1 << 1, 1);

			context->sendPacket("IPv4", packet);
		}

		// void operator = (Azocket _azocket) {
		// 	source_ip = _azocket.source_ip;
		// 	source_port = _azocket.source_port;
		// 	dest_ip = _azocket.dest_ip;
		// 	dest_port = _azocket.dest_port;
		// 	sockfd = _azocket.sockfd;
		// 	seq_num = _azocket.seq_num;
		// 	syscall_id = _azocket.syscall_id;
		// 	backlog = _azocket.backlog;
		// 	state = _azocket.state;
		// }
	};

	// map: int (sockfd) -> Azocket
	std::unordered_map<int, Azocket> sockfdToAzocket;

	struct SipDip {
		struct sockaddr s_addr;
		socklen_t s_addrlen; 
		struct sockaddr d_addr;
		socklen_t d_addrlen;
	};
	
	// map: SipDip -> sockfd
	std::map<struct SipDip, int> SipDipTosockfd;

	typedef enum {
		SYN,
		ACK,
		SYNACK
	} packetType;

	virtual void syscall_socket(UUID syscallUUID, int pid, int type, int protocol) final;
	virtual void syscall_close(UUID syscallUUID, int pid, int sockfd) final;
	virtual int bind(int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
	virtual void implicit_bind(int sockfd, uint32_t dest_ip) final;
	virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) final;
	virtual void syscall_connect(UUID syscallUUID,  int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) final;
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
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
