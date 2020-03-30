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
	this->removeFileDescriptor(pid, sockfd);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(
	UUID syscallUUID, int pid, int sockfd,
	struct sockaddr *addr, socklen_t addrlen) {
	// If the socket descriptor does not exist or was already binded, return -1.
	if (!fds.count(sockfd) || sockfdToAddrInfo.count(sockfd)) {
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

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
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	// If the checks passed, add (socket descriptor, binding) pair into the hash table
	// and put the binding information into the set (hash table) of active bindings.
	sockfdToAddrInfo[sockfd] = {copied_addr, addrlen};
	binded.insert({port, ip});

	this->returnSystemCall(syscallUUID, 0);
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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
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
