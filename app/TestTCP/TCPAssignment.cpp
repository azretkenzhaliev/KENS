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

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol) {
	// We assume that the createFileDescriptor function will always return a valid file descriptor.
	int fd = this->createFileDescriptor(pid);

	if (fd != -1) {
		// If the file descriptor was successfully created make a note of that.
		fds.insert(fd);
		Azocket azocket;
		azocket.sockfd = fd;
		azocket.state = sockstate::STATE_CLOSED;
		sockfdToAzocket[fd] = azocket;
	}

	// Return -1 or the created file descriptor.
	this->returnSystemCall(syscallUUID, fd);
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

int TCPAssignment::bind(int sockfd, struct sockaddr *addr, socklen_t addrlen){
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

	this->returnSystemCall(syscallUUID, bind(sockfd, addr, addrlen));
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
	int port = std::uniform_int_distribution<int>(1025, 65535)(rng);
	
	uint8_t *local_ip;
	int index = this->getHost()->getRoutingTable((uint8_t *)dest_ip);
	this->getHost()->getIPAddr(local_ip, index);

	struct sockaddr_in buf;
	buf.sin_family = AF_INET;
	buf.sin_addr.s_addr = (in_addr_t) *local_ip;
	buf.sin_port = port;
	
	struct sockaddr *local_addr = (struct sockaddr *) &buf;
	socklen_t local_addrlen = sizeof(*local_addr);

	while (bind(sockfd, local_addr, local_addrlen) != 0){
		port = std::uniform_int_distribution<int>(1025, 65535)(rng);
		buf.sin_port = port;
	}
}

void TCPAssignment::syscall_connect(
	UUID syscallUUID,  int pid, int sockfd,
	struct sockaddr *addr, socklen_t addrlen) {
	uint32_t dest_ip = ((struct sockaddr_in*) &addr)->sin_addr.s_addr;
	uint8_t dest_port = ((struct sockaddr_in*) &addr)->sin_port;
	implicit_bind(sockfd, dest_ip);

	sockfdToAzocket[sockfd].dest_ip = dest_ip;
	sockfdToAzocket[sockfd].dest_port = dest_port;

	sockfdToAzocket[sockfd].sendSYNPacket(this); // sockfd, dest ip, ...

	sockfdToAzocket[sockfd].syscall_id = syscallUUID;
	sockfdToAzocket[sockfd].state = sockstate::STATE_SYNSENT;
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
		// this->syscall_connect(syscallUUID, pid, param.param1_int,
		// 		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
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
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
