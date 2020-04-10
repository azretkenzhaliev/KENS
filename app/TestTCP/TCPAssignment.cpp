/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <random>
#include <chrono>


namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

int TCPAssignment::_syscall_socket(UUID syscallUUID, int pid, int type, int protocol) {
	int fd = this->createFileDescriptor(pid);

	if (fd != -1) {
		// If the file descriptor was successfully created make a note of that.
		fds.insert(fd);

		Azocket azocket;
		azocket.pid = pid;
		azocket.sockfd = fd;
		azocket.syscall_id = syscallUUID;
		azocket.state = sockstate::STATE_CLOSED;

		std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
		azocket.seq_num = htonl(std::uniform_int_distribution<uint32_t>(0, UINT32_MAX)(rng));

		azocket.ack_num = 0;

		sockfdToAzocket[fd] = azocket;
	}

	// Return -1 or the created file descriptor.
	return fd;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol) {
	this->returnSystemCall(syscallUUID, _syscall_socket(syscallUUID, pid, type, protocol));
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd) {
	if (fds.find(sockfd) == fds.end()) {
		// If somebody tries to close the socket descriptor which doesn't exist, return -1.
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	if (sockfdToAddrInfo.count(sockfd)) {
		// If the given socket descriptor was binded - unbind it first.
		struct sockaddr addr = sockfdToAddrInfo[sockfd].first;

		// sockfdToAddrInfo for each socket descriptor (key) stores its binding (value).
		// To close a socket descriptor we need to remove its binding from
		// the list of active bindings, which we store in a set (binded).
		uint16_t port = ((struct sockaddr_in*) &addr)->sin_port;
		uint32_t ip = ((struct sockaddr_in*) &addr)->sin_addr.s_addr;
		
		// Remove the (port, ip) binding entry from the set (hash table) of active bindings
		// and the (socket descriptor, binding) key-value pair from the
		// sockfdToAddrInfo hash table.
		binded.erase({port, ip});
		sockfdToAddrInfo.erase(sockfd);
	}

	// Remove the socket descriptor from the set (hash table) of active socket descriptors.
	fds.erase(sockfd);
	sockfdToAzocket.erase(sockfd);
	this->removeFileDescriptor(pid, sockfd);
	this->returnSystemCall(syscallUUID, 0);
}

int TCPAssignment::_syscall_bind(int sockfd, struct sockaddr *addr, socklen_t addrlen) {
	// We decided to copy the given data (binding), so that
	// in case if the data in the given pointer is ever
	// freed without a notice, we'll be safe.
	struct sockaddr copied_addr = *addr;

	uint16_t port = ((struct sockaddr_in*) &copied_addr)->sin_port;
	uint32_t ip = ((struct sockaddr_in*) &copied_addr)->sin_addr.s_addr;

	// If the set of active bindings already contains either of the
	// (port, 0.0.0.0) or (port, ip) pairs, it means that current
	// binding is not allowed to happen, so return -1.
	if (binded.find({port, 0}) != binded.end() || binded.find({port, ip}) != binded.end()) {
		return -1;
	}

	// If the checks passed, add (socket descriptor, binding) pair into the hash table
	// and put the binding information into the set (hash table) of active bindings.
	sockfdToAddrInfo[sockfd] = {copied_addr, addrlen};

	IPPortToSockfd[{ip, port}] = sockfd;

	binded.insert({port, ip});

	sockfdToAzocket[sockfd].source_ip = ip;
	sockfdToAzocket[sockfd].source_port = port;
	return 0;
}

void TCPAssignment::syscall_bind(
	UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t addrlen) {
	// If the socket descriptor does not exist or was already binded, return -1.
	if (!fds.count(sockfd) || sockfdToAddrInfo.count(sockfd)) {
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	this->returnSystemCall(syscallUUID, _syscall_bind(sockfd, addr, addrlen));
}

void TCPAssignment::syscall_getsockname(
	UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t* addrlen) {
	// If the socket descriptor does not exist or was not binded, return -1.
	if (!fds.count(sockfd) || !sockfdToAddrInfo.count(sockfd)) {
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	// Fill the content of the given pointers with information
	// from the sockfdToAddrInfo hash table.
	*addr = sockfdToAddrInfo[sockfd].first;
	*addrlen = sockfdToAddrInfo[sockfd].second;

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::implicit_bind(int sockfd, uint32_t dest_ip) {
	std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
	uint16_t local_port = std::uniform_int_distribution<uint16_t>(1025, 65535)(rng);

	uint8_t *dest_ip_by_8 = (uint8_t *) malloc(sizeof(uint32_t));

	dest_ip_by_8[0] = (dest_ip >> 0) & 0xff;
	dest_ip_by_8[1] = (dest_ip >> 8) & 0xff;
	dest_ip_by_8[2] = (dest_ip >> 16) & 0xff;
	dest_ip_by_8[3] = (dest_ip >> 24) & 0xff;

	uint8_t *local_ip_by_8 = (uint8_t *) malloc(sizeof(uint32_t));
	int index = this->getHost()->getRoutingTable(dest_ip_by_8);
	this->getHost()->getIPAddr(local_ip_by_8, index);

	uint32_t local_ip = (local_ip_by_8[0]
		+ (local_ip_by_8[1] << 8)
		+ (local_ip_by_8[2] << 16)
		+ (local_ip_by_8[3] << 24));

	local_ip = ntohl(local_ip);
	local_port = ntohs(local_port);

	struct sockaddr_in buf;
	buf.sin_family = AF_INET;
	buf.sin_addr.s_addr = local_ip;
	buf.sin_port = local_port;
	
	struct sockaddr *local_addr = (struct sockaddr *) &buf;
	socklen_t local_addrlen = sizeof(*local_addr);

	while (_syscall_bind(sockfd, local_addr, local_addrlen) != 0){
		local_port = ntohs(std::uniform_int_distribution<int>(1025, 65535)(rng));
		buf.sin_port = local_port;
	}
}

void TCPAssignment::syscall_connect(
	UUID syscallUUID,  int pid, int sockfd,
	struct sockaddr *addr, socklen_t addrlen) {
	uint32_t dest_ip = ntohl(((struct sockaddr_in *) addr)->sin_addr.s_addr);
	uint16_t dest_port = ntohs(((struct sockaddr_in *) addr)->sin_port);
	implicit_bind(sockfd, dest_ip);

	sockfdToAzocket[sockfd].dest_ip = dest_ip;
	sockfdToAzocket[sockfd].dest_port = dest_port;

	SipDip sipdip = getSipDip(sockfdToAzocket[sockfd].source_ip, sockfdToAzocket[sockfd].source_port, sockfdToAzocket[sockfd].dest_ip, sockfdToAzocket[sockfd].dest_port);
	SipDipToSockfd[sipdip] = sockfd;

	sendSYNPacket(sockfdToAzocket[sockfd]);

	sockfdToAzocket[sockfd].syscall_id = syscallUUID;
	sockfdToAzocket[sockfd].state = sockstate::STATE_SYNSENT;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, 
	struct sockaddr *addr, socklen_t* addrlen) {

	struct sockaddr_in *buf = new struct sockaddr_in;
	buf->sin_family = AF_INET;
	buf->sin_addr.s_addr = htonl(sockfdToAzocket[sockfd].dest_ip);
	buf->sin_port = htons(sockfdToAzocket[sockfd].dest_port);

	*addr = *((struct sockaddr *) buf);
	*addrlen = sizeof(*addr);

	this->returnSystemCall(syscallUUID, 0);
}

Packet* TCPAssignment::makePacket(struct Azocket &azocket, PacketType type) {
	// 14 - Ethernet header
	// 20 - IP header structure

	Packet *packet = this->allocatePacket(54);

	uint32_t source_ip = htonl(azocket.source_ip);
	uint16_t source_port = htons(azocket.source_port);
	uint32_t dest_ip = htonl(azocket.dest_ip);
	uint16_t dest_port = htons(azocket.dest_port);
	uint32_t seq_num = htonl(azocket.seq_num);
	uint32_t ack_num = htonl(azocket.ack_num);

	// azocket.seq_num++;
	// uint32_t ack_num = azocket.ack_num;

	uint16_t total_length = htons(20);
	packet->writeData(14 + 2, &total_length, 2);

	packet->writeData(14 + 12, &source_ip, 4);
	packet->writeData(14 + 16, &dest_ip, 4);
	packet->writeData(14 + 20 + 0, &source_port, 2);
	packet->writeData(14 + 20 + 2, &dest_port, 2);
	packet->writeData(14 + 20 + 4, &seq_num, 4);
	packet->writeData(14 + 20 + 8, &ack_num, 4);

	uint8_t data_offset = 5 << 4;
	packet->writeData(14 + 20 + 12, &data_offset, 1);

	uint8_t flags = type;
	packet->writeData(14 + 20 + 13, &flags, 1);

	uint16_t window_size = htons(51200);
	packet->writeData(14 + 20 + 14, &window_size, 2);

	size_t tcp_len = 20;
	uint8_t *tcp_seg = (uint8_t *) malloc(tcp_len);
	packet->readData(14 + 20, tcp_seg, tcp_len);

	uint16_t checksum = htons(~NetworkUtil::tcp_sum(source_ip, dest_ip, tcp_seg, tcp_len));
	packet->writeData(14 + 20 + 16, &checksum, 2);

	return packet;
}

void TCPAssignment::sendSYNPacket(struct Azocket &azocket) {
	Packet *packet = makePacket(azocket, PacketType::SYN);
	this->sendPacket("IPv4", packet);
}

void TCPAssignment::sendSYNACKPacket(struct Azocket &azocket) {
	Packet *packet = makePacket(azocket, PacketType::SYNACK);
	this->sendPacket("IPv4", packet);
}

void TCPAssignment::sendACKPacket(struct Azocket &azocket) {
	Packet *packet = makePacket(azocket, PacketType::ACK);
	this->sendPacket("IPv4", packet);
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		 this->syscall_connect(syscallUUID, pid, param.param1_int,
		 		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

uint8_t TCPAssignment::getFlags(Packet *packet) {
	uint8_t flags = 0;
	packet->readData(14 + 20 + 13, &flags, 1);
	return flags;
}

TCPAssignment::SipDip TCPAssignment::getSipDip(uint32_t source_ip, uint16_t source_port, uint32_t dest_ip, uint16_t dest_port) {
	return SipDip(source_ip, source_port, dest_ip, dest_port);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet *packet) {
	uint8_t flags = getFlags(packet);

	uint32_t source_ip = 0;
	uint16_t source_port = 0;
	uint32_t dest_ip = 0;
	uint16_t dest_port = 0;
	uint32_t seq_num = 0;

	packet->readData(14 + 12, &source_ip, 4);
	packet->readData(14 + 16, &dest_ip, 4);
	packet->readData(14 + 20 + 0, &source_port, 2);
	packet->readData(14 + 20 + 2, &dest_port, 2);
	packet->readData(14 + 20 + 4, &seq_num, 4);

	freePacket(packet);

	source_ip = ntohl(source_ip);
	source_port = ntohs(source_port);
	dest_ip = ntohl(dest_ip);
	dest_port = ntohs(dest_port);
	seq_num = ntohl(seq_num);

	int sockfd;
	SipDip sipdip;

	switch ((uint16_t) flags) {
		case PacketType::FIN: {
			break;
		}
		case PacketType::SYN: { // server accepts connection
			sockfd = IPPortToSockfd[{dest_ip, dest_port}];
			int new_sockfd = _syscall_socket(sockfdToAzocket[sockfd].syscall_id, sockfdToAzocket[sockfd].pid, 0, 0);

			sockfdToAzocket[new_sockfd].source_ip = dest_ip;
			sockfdToAzocket[new_sockfd].source_port = dest_port;
			sockfdToAzocket[new_sockfd].dest_ip = source_ip;
			sockfdToAzocket[new_sockfd].dest_port = source_port;

			sipdip = getSipDip(source_ip, source_port, dest_ip, dest_port);
			SipDipToSockfd[sipdip] = new_sockfd;
			
			sendSYNACKPacket(sockfdToAzocket[new_sockfd]);

			sockfdToAzocket[new_sockfd].state = sockstate::STATE_SYN_RCVD;
			break;
		}
		case PacketType::SYNACK: { // client established connection
			sipdip = getSipDip(source_ip, source_port, dest_ip, dest_port);
			sockfd = SipDipToSockfd[sipdip];
			
			sockfdToAzocket[sockfd].ack_num = seq_num + 1;
			sendACKPacket(sockfdToAzocket[sockfd]);

			sockfdToAzocket[sockfd].state = sockstate::STATE_ESTAB;
			this->returnSystemCall(sockfdToAzocket[sockfd].syscall_id, 0);
			break;
		}
		case PacketType::ACK: {
			sipdip = getSipDip(source_ip, source_port, dest_ip, dest_port);
			sockfd = SipDipToSockfd[sipdip];
			sockfdToAzocket[sockfd].state = sockstate::STATE_ESTAB;
			break;
		}
	}
}

void TCPAssignment::timerCallback(void* payload) {

}
}