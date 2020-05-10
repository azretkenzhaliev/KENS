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
#include <E/E_TimeUtil.hpp>
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

int TCPAssignment::_syscall_socket(int pid) {
	int fd = this->createFileDescriptor(pid);
#if 0
	std::cout << "_syscall_socket -> " << fd << " " << pid << std::endl;
#endif
	if (fd != -1) {
		AzocketKey key(fd, pid);
		azocketKeys.insert(key);
		azocketKeyToAzocket[key] = Azocket(key, TCP_CLOSE);
	}

	return fd;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int type, int protocol) {
	this->returnSystemCall(syscallUUID, _syscall_socket(pid));
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd) {
	AzocketKey key(sockfd, pid);

	if (!azocketKeys.count(key)) {
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	Azocket azocket = azocketKeyToAzocket[key];
	if (azocket.state == TCP_ESTABLISHED) {
#if 0
		std::cout << "if state: " << azocketKeyToAzocket[key].state << std::endl;
#endif
		dispatchPacket(azocketKeyToAzocket[key], TH_FIN | TH_ACK);

		azocketKeyToAzocket[key].state = TCP_FIN_WAIT1;
	} else if (azocket.state == TCP_CLOSE_WAIT) {
#if 0
		std::cout << "elif state: " << azocketKeyToAzocket[key].state << std::endl;
#endif
		dispatchPacket(azocketKeyToAzocket[key], TH_FIN | TH_ACK);

		azocketKeyToAzocket[key].state = TCP_LAST_ACK;
	} else{
#if 0
		std::cout << "else state: " << azocketKeyToAzocket[key].state << std::endl;
#endif

		if (azocketKeyToAddrInfo.count(key)) {
			Address address(azocketKeyToAddrInfo[key]);
			bindedAddresses.erase(address);
			azocketKeyToAddrInfo.erase(key);
		}

		azocketKeys.erase(key);
		azocketKeyToAzocket.erase(key);
	}

	this->removeFileDescriptor(pid, sockfd);
	this->returnSystemCall(syscallUUID, 0);
}

int TCPAssignment::_syscall_bind(int sockfd, int pid, struct sockaddr *addr, socklen_t addrlen) {
	AddrInfo addr_info(*addr, addrlen);
	Address address(addr_info);
	Address address_zero(0U, address.port);

#if 0
	std::cout << address.port << " " << address.ip << std::endl;
	std::cout << address_zero.port << " " << address_zero.ip << std::endl;
	std::cout << bindedAddresses.size() << std::endl;
	for (auto it: bindedAddresses) {
		std::cout << it.ip << " " << it.port << std::endl;
	}
	std::cout << "Checking for overlap..." << std::endl;
#endif
	if (bindedAddresses.count(address_zero) || bindedAddresses.count(address)) {
#if 0
		std::cout << "FOUND OVERLAP!" << std::endl;
#endif
		return -1;
	}

	AzocketKey key(sockfd, pid);

	azocketKeyToAddrInfo[key] = addr_info;
	azocketKeyToAzocket[key].addressKey.source = address;

	bindedAddresses.insert(address);

#if 0
	std::cout << "Successful binding of " << address.ip << " " << address.port << "\n";
#endif
	return 0;
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
#if 0
	std::cout << "sockfd = " << sockfd << std::endl; 
#endif
	AzocketKey key(sockfd, pid);
	if (!azocketKeys.count(key) || azocketKeyToAddrInfo.count(key)) {
#if 0
		std::cout << "Something wrong here..." << std::endl;
		std::cout << azocketKeyToAddrInfo.count(key) << std::endl;
		Address address(azocketKeyToAddrInfo[key]);
		std::cout << address.ip << " " << address.port << std::endl;
#endif

		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	this->returnSystemCall(syscallUUID, _syscall_bind(sockfd, pid, addr, addrlen));
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) {
	AzocketKey key(sockfd, pid);

	if (!azocketKeys.count(key) || !azocketKeyToAddrInfo.count(key)) {
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	*addr = azocketKeyToAddrInfo[key].addr;
	*addrlen = azocketKeyToAddrInfo[key].addrlen;

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::implicit_bind(int sockfd, int pid, uint32_t dest_ip) {
	uint32_t local_ip = 0;

	int index = this->getHost()->getRoutingTable((uint8_t *) &dest_ip);
	this->getHost()->getIPAddr((uint8_t *) &local_ip, index);

	local_ip = ntohl(local_ip);

#if 0
	std::cout << "implicit binding to -> " << local_ip << " " << local_port << "\n";
	std::cout << Address(local_ip, local_port) << std::endl;
#endif

	uint16_t local_port;
	AddrInfo addr_info;

	std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
	do {
		local_port = std::uniform_int_distribution<uint16_t>(1025, UINT16_MAX)(rng);
		addr_info = AddrInfo(Address(local_ip, local_port));
	} while (_syscall_bind(sockfd, pid, &addr_info.addr, addr_info.addrlen) != 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
	AzocketKey key(sockfd, pid);
	Azocket &azocket = azocketKeyToAzocket[key];
#if 0
	std::cout << "Called connect on (" << key.sockfd << ", " << key.pid << ")\n";
#endif

	Address dest_address(AddrInfo(*addr, addrlen));
	if (!azocketKeyToAddrInfo.count(key)) {
		implicit_bind(sockfd, pid, dest_address.ip);
	}

	AddressKey &address_key = azocket.addressKey;
	address_key.dest = dest_address;

#if 0
	std::cout << "Implicitly created a socket with AddressKey = ([" << address_key.source.ip << ", " << address_key.source.port << "], [" << address_key.dest.ip << ", " << address_key.dest.port << "])\n";
#endif
	addressKeyToAzocketKey[address_key] = key;

	dispatchPacket(azocket, TH_SYN);

	azocket.syscall_id = syscallUUID;
	azocket.state = TCP_SYN_SENT;

#if 0
	std::cout << "SYNSENT from " << address_key.source.ip << " to " << address_key.dest.ip << "\n";
#endif
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
	AzocketKey key(sockfd, pid);
	Azocket &azocket = azocketKeyToAzocket[key];

	azocket.listenControl.backlog = backlog;
	azocket.state = TCP_LISTEN;

	listenAddressToAzocketKey[azocket.addressKey.source] = key;

#if 0
	std::cout << "Listening on (" << sockfd << ", " << pid << "; ip = " << azocket.addressKey.source.ip << ", port = " << azocket.addressKey.source.port << ") with backlog = " << backlog << "\n";
	std::cout << "No remote address should be set, checking: (" << azocket.addressKey.dest.ip << ", " << azocket.addressKey.dest.port << ")\n";
#endif

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	AzocketKey key(sockfd, pid);
	Azocket &azocket = azocketKeyToAzocket[key];

	if (azocket.state != TCP_LISTEN) {
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

#if 0
	std::cout << "Accept called for " << sockfd << ", " << pid << ", " << syscallUUID << std::endl;
#endif

	std::vector<int> &child_sockfds = azocket.listenControl.child_sockfds;
	auto it = std::find_if(child_sockfds.begin(), child_sockfds.end(), [&](int child_sockfd) {
		AzocketKey child_key(child_sockfd, pid);
		return azocketKeyToAzocket[child_key].state == TCP_ESTABLISHED
			|| azocketKeyToAzocket[child_key].state == TCP_CLOSE_WAIT;
	});
	if (it != child_sockfds.end()) {
		int child_sockfd = *it;
		child_sockfds.erase(it);

		_syscall_getpeername(child_sockfd, pid, addr, addrlen);

#if 0
		sockaddr_in addr_in = *((sockaddr_in *) addr);
		std::cout << "(1) Triple checking the address: " << addr_in.sin_addr.s_addr << " " << addr_in.sin_port << "\n";
		std::cout << "(2) Triple checking the address: " << ntohl(addr_in.sin_addr.s_addr) << " " << ntohs(addr_in.sin_port) << "\n";

		Address address(AddrInfo(*addr, *addrlen));
		std::cout << "(3) Triple checking the address -> " << address.ip << " " << address.port << "\n";

		std::cout << "Accept returns " << child_sockfd << "\n";
#endif
		this->returnSystemCall(syscallUUID, child_sockfd);
		return;
	}

#if 0
	std::cout << "Accept blocked\n";
#endif
	azocket.acceptControl.addr = addr;
	azocket.acceptControl.addrlen = addrlen;
	azocket.acceptControl.blocked = true;
	azocket.acceptControl.syscall_id = syscallUUID;
}

void TCPAssignment::_syscall_getpeername(int sockfd, int pid, struct sockaddr *addr, socklen_t* addrlen) {
	AzocketKey key(sockfd, pid);
	
	Address &dest = azocketKeyToAzocket[key].addressKey.dest;
#if 0
	std::cout << "For " << sockfd << ", " << pid << " dest is " << dest.ip << ", " << dest.port << std::endl;
#endif

	AddrInfo addr_info(dest);
	*addr = addr_info.addr;
	*addrlen = addr_info.addrlen;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) {
	_syscall_getpeername(sockfd, pid, addr, addrlen);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, const void *buf, size_t count){
	AzocketKey key(sockfd, pid);
	Azocket &azocket = azocketKeyToAzocket[key];

	int written = writeData(azocket, buf, count);
	this->returnSystemCall(syscallUUID, written);
}

int TCPAssignment::writeData(Azocket &azocket, const void *buf, size_t count){
	// return how many bytes actually has been written
	int written = 0;
	// std::cout << "count: " << count << std::endl; 
	uint8_t *p = (uint8_t *) buf;
	for (int i = 0; i < count; i++){
		azocket.senderBuffer.buf.push_back(*p);
		p ++;
		written += 1;
	}

	// uint8_t *p = (uint8_t *) buf;
	// for (int i = 0; i < count; i++) {
	// 	std::cout << p[i] << std::endl;
	// 	azocket.senderBuffer.buf.push_back(p[i]);
	// 	written += 1;
	// }

	// std::cout << "written: " << written << std::endl;
	dispatchWritePackets(azocket);
	// std::cout << written << std::endl;
	return written;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void *buf, size_t count){
	AzocketKey key(sockfd, pid);
	Azocket &azocket = azocketKeyToAzocket[key];

	if (azocket.receiverBuffer.buf.size() < count){
		azocket.receiverBuffer.blocked = true;
		azocket.receiverBuffer.uuid = syscallUUID;
		azocket.receiverBuffer.count = count;
		azocket.receiverBuffer.user_buf = buf;
		return;
	}

	for (int i = 0; i < count; i++){
		memcpy(buf + i, &azocket.receiverBuffer.buf[0], 1);
		azocket.receiverBuffer.buf.pop_front();
	}

	azocket.receiverBuffer.window_size += count;
	this->returnSystemCall(syscallUUID, count);
}


Packet* TCPAssignment::makePacket(struct Azocket &azocket, uint8_t type, int bytes) {
#if 0
	std::cout << "Making packet of type " << (uint16_t) type;
	std::cout << " and sending from " << azocket.addressKey.source;
	std::cout << " to " << azocket.addressKey.dest << "\n";
#endif

	Packet *packet = this->allocatePacket(54 + bytes);

	AddressKey address_key = azocket.addressKey;
	address_key.toNetwork();

	int byte_sequence = azocket.senderBuffer.acked_bytes + azocket.senderBuffer.not_sent;
	uint32_t seq_num = htonl(azocket.seq_num + byte_sequence);

	uint16_t total_length = htons(20);
	packet->writeData(14 + 2, &total_length, 2);

	if (type != TH_SYN) {
		uint32_t ack_num = htonl(azocket.ack_num);
		packet->writeData(14 + 20 + 8, &ack_num, 4);
	}

	packet->writeData(14 + 12, &address_key.source.ip, 4);
	packet->writeData(14 + 16, &address_key.dest.ip, 4);
	packet->writeData(14 + 20 + 0, &address_key.source.port, 2);
	packet->writeData(14 + 20 + 2, &address_key.dest.port, 2);


	packet->writeData(14 + 20 + 4, &seq_num, 4);

	uint8_t data_offset = 5 << 4;
	packet->writeData(14 + 20 + 12, &data_offset, 1);

	uint8_t flags = type;
	packet->writeData(14 + 20 + 13, &flags, 1);

	uint16_t window_size = htons(azocket.receiverBuffer.window_size);
	packet->writeData(14 + 20 + 14, &window_size, 2);

	for (int i = 0; i < bytes; i++){
		packet->writeData(14 + 20 + 20 + i, &azocket.senderBuffer.buf[azocket.senderBuffer.not_sent + i], 1);
	}
	// uint16_t write_data = htons(azocket.senderBuffer.buf[azocket.senderBuffer.not_sent]);
	// packet->writeData(14 + 20 + 20, &write_data, bytes);

	size_t tcp_len = 20 + bytes;
	// size_t tcp_len = 20;
	uint8_t *tcp_seg = (uint8_t *) malloc(tcp_len);
	packet->readData(14 + 20, tcp_seg, tcp_len);

	uint16_t checksum = htons(~NetworkUtil::tcp_sum(address_key.source.ip, address_key.dest.ip, tcp_seg, tcp_len));

	packet->writeData(14 + 20 + 16, &checksum, 2);

	return packet;
}

void TCPAssignment::dispatchPacket(struct Azocket &azocket, uint8_t type) {
	Packet *packet = makePacket(azocket, type);
	this->sendPacket("IPv4", packet);
}

void TCPAssignment::dispatchWritePackets(struct Azocket &azocket){
	int deq_size = static_cast<int>(azocket.senderBuffer.buf.size());
	int bytes_to_send = std::min(deq_size  - azocket.senderBuffer.not_sent, azocket.senderBuffer.can_receive);

	while (bytes_to_send != 0){
		int bytes = std::min(512, bytes_to_send);
		Packet *packet = makePacket(azocket, TH_ACK, bytes);
		// std::cout << "sending packet" << std::endl;
		this->sendPacket("IPv4", packet);
		// std::cout << "sent packet" << std::endl;
		bytes_to_send -= bytes;
		azocket.senderBuffer.not_sent += bytes;
	}

	azocket.senderBuffer.can_receive -= bytes_to_send;
}

void TCPAssignment::ackWriteBytes(struct Azocket &azocket, int ack_num, int window_size){
	int bytes_to_ack = ack_num - azocket.seq_num - azocket.senderBuffer.acked_bytes;
	for (int i = 0; i < bytes_to_ack; i++){
		azocket.senderBuffer.buf.pop_front();
	}
	azocket.senderBuffer.acked_bytes += bytes_to_ack;
	azocket.senderBuffer.not_sent -= bytes_to_ack;
	azocket.senderBuffer.can_receive = window_size;

	dispatchWritePackets(azocket);
}

void TCPAssignment::receiveWriteBytes(AddressKey &address_key, uint32_t & seq_num, Packet *packet){
	AzocketKey &key = addressKeyToAzocketKey[address_key];
	Azocket &azocket = azocketKeyToAzocket[key];

	int count = packet->getSize() - 54;

	for (int i = 0; i < count; i++){
		uint8_t p = 0;
		packet->readData(14 + 20 + 20 + i, &p, 1);
		azocket.receiverBuffer.buf.push_back(p);
	}
	int buffer_size = (int) azocket.receiverBuffer.buf.size();
	azocket.receiverBuffer.window_size = 51200 - buffer_size;
	azocket.ack_num = seq_num + count;

	if (azocket.receiverBuffer.blocked){
		if (azocket.receiverBuffer.buf.size() >= azocket.receiverBuffer.count){
			
			// uint8_t *p = (uint8_t *) azocket.receiverBuffer.user_buf;
			// for (int i = 0; i < azocket.receiverBuffer.count; i++){
			// 	memcpy(&p[i], &azocket.receiverBuffer.buf[0], 1);
			// 	azocket.receiverBuffer.buf.pop_front();
			// }

			for (int i = 0; i < azocket.receiverBuffer.count; i++){
				memcpy(azocket.receiverBuffer.user_buf + i, &azocket.receiverBuffer.buf[0], 1);
				azocket.receiverBuffer.buf.pop_front();
			}

			azocket.receiverBuffer.window_size += azocket.receiverBuffer.count;
			this->returnSystemCall(azocket.receiverBuffer.uuid, azocket.receiverBuffer.count);
		}
	}
	
	this->freePacket(packet);

	Packet *new_packet = makePacket(azocket, TH_ACK);
	this->sendPacket("IPv4", new_packet);
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
// #if 0
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
// #endif
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
		 		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
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

bool TCPAssignment::readPacket(Packet *packet, uint8_t &flags, AddressKey &address_key, uint32_t &seq_num, uint32_t &ack_num, uint16_t &window_size) {
	packet->readData(14 + 20 + 13, &flags, 1);
	packet->readData(14 + 12, &address_key.dest.ip, 4);
	packet->readData(14 + 16, &address_key.source.ip, 4);
	packet->readData(14 + 20 + 0, &address_key.dest.port, 2);
	packet->readData(14 + 20 + 2, &address_key.source.port, 2);
	packet->readData(14 + 20 + 4, &seq_num, 4);
	packet->readData(14 + 20 + 8, &ack_num, 4);
	packet->readData(14 + 20 + 14, &window_size, 2);

	seq_num = ntohl(seq_num);
	ack_num = ntohl(ack_num);
	window_size = ntohs(window_size);

	uint16_t given_checksum = 0;
	packet->readData(14 + 20 + 16, &given_checksum, 2);

	uint16_t null_checksum = 0;
	packet->writeData(14 + 20 + 16, &null_checksum, 2);

	size_t tcp_len = packet->getSize() - 34;
	uint8_t *tcp_seg = (uint8_t *) malloc(tcp_len);
	packet->readData(14 + 20, tcp_seg, tcp_len);

	freePacket(packet);

	uint16_t checksum = htons(~NetworkUtil::tcp_sum(address_key.dest.ip, address_key.source.ip, tcp_seg, tcp_len));

	address_key.toHost();

	return checksum == given_checksum;
}

void TCPAssignment::handleFIN(const AddressKey &address_key, const uint32_t &seq_num, const uint32_t &ack_num) {

}

void TCPAssignment::handleSYN(const AddressKey &address_key, const uint32_t &seq_num, const uint32_t &ack_num) {
	Address source = address_key.source;
	Address source_zero = source;
	source_zero.ip = 0;

#if 0
	std::cout << "source vs source_zero: " << listenAddressToAzocketKey.count(source) << " " << listenAddressToAzocketKey.count(source_zero) << std::endl;
#endif

	AzocketKey &key = listenAddressToAzocketKey.count(source_zero) ? listenAddressToAzocketKey[source_zero] : listenAddressToAzocketKey[source]; // assumption that such listening socket exists
	Azocket &azocket = azocketKeyToAzocket[key];

#if 0
	std::cout << "SYN: " << key.sockfd << " " << key.pid << " " << azocket.listenControl.backlog << std::endl;
#endif

	if (azocket.state != TCP_LISTEN) {
		AzocketKey &key = addressKeyToAzocketKey[address_key];
		Azocket &azocket = azocketKeyToAzocket[key];
		AddressKey &new_address_key = azocket.addressKey;

		new_address_key = address_key;
		azocket.ack_num = seq_num + 1;
		addressKeyToAzocketKey[address_key] = key;
		dispatchPacket(azocket, TH_SYN | TH_ACK);

		azocket.state = TCP_SYN_RECV;
		return;
	}
	if (azocket.listenControl.backlog == 0) {
#if 0
		std::cout << "SYN The main concern for (1) that we considered is:Packet Denied\n";
#endif
		return;
	}

	int new_sockfd = _syscall_socket(key.pid);
	azocket.listenControl.child_sockfds.push_back(new_sockfd);
	azocket.listenControl.backlog--;

	AzocketKey new_key = {new_sockfd, key.pid};
	Azocket &new_azocket = azocketKeyToAzocket[new_key];
	AddressKey &new_address_key = new_azocket.addressKey;

	new_azocket.listenControl.parent_sockfd = key.sockfd;
	new_address_key = address_key;
	new_azocket.ack_num = seq_num + 1;

	azocketKeyToAddrInfo[new_key] = AddrInfo(address_key.source);

#if 0
	std::cout << "SYN: " << seq_num << " " << ack_num << " " << new_azocket.seq_num << "\n";
#endif

	addressKeyToAzocketKey[new_address_key] = new_key;
	dispatchPacket(new_azocket, TH_SYN | TH_ACK);

	new_azocket.state = TCP_SYN_RECV;
}

void TCPAssignment::handleACK(const AddressKey &address_key, const uint32_t &seq_num, const uint32_t &ack_num, uint16_t &window_size) {
	AzocketKey &key = addressKeyToAzocketKey[address_key];
	Azocket &azocket = azocketKeyToAzocket[key];

	if (azocket.state == TCP_ESTABLISHED) {
		ackWriteBytes(azocket, ack_num, window_size);
		return;
	} 
	
#if 0
	std::cout << "ACK: " << key.sockfd << " " << ack_num << " " << azocketKeyToAzocket[key].seq_num << "\n";
#endif
	if (ack_num != azocket.seq_num + 1) {
#if 0
		std::cout << "ACK Packet Denied\n";
#endif
		return;
	}

	if (azocket.state == TCP_CLOSING) {
		azocket.state = TCP_TIME_WAIT;
		azocket.seq_num++;

		this->addTimer((void *) &azocket, TimeUtil::makeTime(2, TimeUtil::MINUTE));
		return;
	} else if (azocket.state == TCP_FIN_WAIT1) {
#if 0
		std::cout << "ACK: TCP_FIN_WAIT1";
#endif
		azocket.state = TCP_FIN_WAIT2;
		azocket.seq_num++;

		return;
	} else if (azocket.state == TCP_LAST_ACK) {
#if 0
		std::cout << "ACK: TCP_LAST_ACK\n";
#endif

		timerCallback((void *) &azocket);

		return;
	}

	if (azocket.state != TCP_SYN_RECV) {
		return;
	}

	azocket.state = TCP_ESTABLISHED;

	int parent_sockfd = azocket.listenControl.parent_sockfd;
	AzocketKey parent_key = {parent_sockfd, key.pid};
	Azocket &parent_azocket = azocketKeyToAzocket[parent_key];
	parent_azocket.listenControl.backlog++;

#if 0
	std::cout << "ACK: " << parent_sockfd << " " << key.pid << " " << parent_azocket.listenControl.backlog << std::endl;
#endif

	if (parent_azocket.acceptControl.blocked) {
		std::vector<int> &child_sockfds = parent_azocket.listenControl.child_sockfds;
		auto it = std::find_if(child_sockfds.begin(), child_sockfds.end(), [&](const int &child_sockfd) {
			return child_sockfd == key.sockfd;
		});
		child_sockfds.erase(it);

		_syscall_getpeername(key.sockfd, key.pid,
			parent_azocket.acceptControl.addr,
			parent_azocket.acceptControl.addrlen
		);
		parent_azocket.acceptControl.blocked = false;
#if 0
		std::cout << "returns accept: "<< parent_azocket.acceptControl.syscall_id << " " << key.sockfd << std::endl;
#endif
		this->returnSystemCall(parent_azocket.acceptControl.syscall_id, key.sockfd);
	}

	azocket.seq_num++;
}

void TCPAssignment::handleFINACK(const AddressKey &address_key, const uint32_t &seq_num, const uint32_t &ack_num) {
	AzocketKey &key = addressKeyToAzocketKey[address_key];
	Azocket &azocket = azocketKeyToAzocket[key];

#if 0
	std::cout << "FINACK: " << key.sockfd << " " << ack_num << " " << azocketKeyToAzocket[key].seq_num << "\n";
	std::cout <<"state: " << azocket.state << std::endl;
#endif

	if (azocket.state == TCP_FIN_WAIT1) {
		azocket.state = TCP_CLOSING;
		azocket.ack_num = seq_num + 1;
		azocket.seq_num++;

		dispatchPacket(azocket, TH_ACK);
	} else if (azocket.state == TCP_FIN_WAIT2) {
#if 0
		std::cout << "state: " << "TCP_FIN_WAIT2" << std::endl;
#endif

		azocket.ack_num = seq_num + 1;

		dispatchPacket(azocket, TH_ACK);

		azocket.state = TCP_TIME_WAIT;
		this->addTimer((void *) &azocketKeyToAzocket[key], TimeUtil::makeTime(2, TimeUtil::MINUTE));
	} else if (azocket.state == TCP_ESTABLISHED) {
#if 0
		std::cout << "state: " << "TCP_ESTABLISHED" << std::endl;
#endif

		azocket.ack_num = seq_num + 1;

		dispatchPacket(azocket, TH_ACK);

		azocket.state = TCP_CLOSE_WAIT;
	}
}

void TCPAssignment::handleSYNACK(const AddressKey &address_key, const uint32_t &seq_num, const uint32_t &ack_num) {
	AzocketKey &key = addressKeyToAzocketKey[address_key];
	Azocket &azocket = azocketKeyToAzocket[key];

#if 0
	std::cout << "SYNACK: " << key.sockfd << " " << ack_num << " " << azocketKeyToAzocket[key].seq_num << "\n";
#endif
	if (ack_num != azocket.seq_num + 1) {
#if 0
		std::cout << "SYNACK Packet Denied\n";
#endif
		return;
	}
	
	azocket.ack_num = seq_num + 1;
	azocket.seq_num++;
	dispatchPacket(azocket, TH_ACK);

	azocket.state = TCP_ESTABLISHED;

	this->returnSystemCall(azocket.syscall_id, 0);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet *packet) {
	uint8_t flags = 0;
	AddressKey address_key;
	uint32_t seq_num = 0;
	uint32_t ack_num = 0;
	uint16_t window_size = 0;

	// if (packet->getSize() > 54){
	// 	std::cout << "packet size: " << packet->getSize() << std::endl;
	// }
	Packet *packet_clone = this->clonePacket(packet);

	if (!readPacket(packet, flags, address_key, seq_num, ack_num, window_size)) {
		return;
	}

	if (packet->getSize() > 54){
		receiveWriteBytes(address_key, seq_num, packet_clone);
		return;
	}
	this->freePacket(packet_clone);

#if 0
	std::cout << "Packet came to me (" << address_key.source.ip << ", " << address_key.source.port << ") from (" << address_key.dest.ip << ", " << address_key.dest.port << ")\n";
#endif

	switch (flags) {
		case TH_FIN: {
#if 0
			handleFIN(address_key, seq_num, ack_num);
#endif
			break;
		}
		case TH_FIN | TH_ACK: {
			handleFINACK(address_key, seq_num, ack_num);
			break;
		}
		case TH_SYN: {
			handleSYN(address_key, seq_num, ack_num);
			break;
		}
		case TH_SYN | TH_ACK: {
			handleSYNACK(address_key, seq_num, ack_num);
			break;
		}
		case TH_ACK: {
			handleACK(address_key, seq_num, ack_num, window_size);
		}
	}
}

void TCPAssignment::timerCallback(void* payload) {
	Azocket* azocket = (Azocket *) payload;
	AzocketKey key = azocket->key;
#if 0
	std::cout << "deleting key: " << key.sockfd << std::endl;
#endif

	if (azocketKeyToAddrInfo.count(key)) {
		Address address(azocketKeyToAddrInfo[key]);
		bindedAddresses.erase(address);
		azocketKeyToAddrInfo.erase(key);
	}

	azocketKeys.erase(key);
	azocketKeyToAzocket.erase(key);
}
}
