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

int TCPAssignment::_syscall_socket(int pid) {
	int fd = this->createFileDescriptor(pid);
	// std::cout << "_syscall_socket -> " << fd << " " << pid << std::endl;

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

	if (azocketKeyToAddrInfo.count(key)) {
		Address address(azocketKeyToAddrInfo[key]);
		bindedAddresses.erase(address);
		azocketKeyToAddrInfo.erase(key);
	}

	azocketKeys.erase(key);
	azocketKeyToAzocket.erase(key);

	this->removeFileDescriptor(pid, sockfd);
	this->returnSystemCall(syscallUUID, 0);
}

int TCPAssignment::_syscall_bind(int sockfd, int pid, struct sockaddr *addr, socklen_t addrlen) {
	AddrInfo addr_info(*addr, addrlen);
	Address address(addr_info);
	Address address_zero(0U, address.port);

	// std::cout << address.port << " " << address.ip << std::endl;
	// std::cout << address_zero.port << " " << address_zero.ip << std::endl;
	// std::cout << bindedAddresses.size() << std::endl;
	// for (auto it: bindedAddresses) {
	// 	// std::cout << it.ip << " " << it.port << std::endl;
	// }
	// std::cout << "Checking for overlap..." << std::endl;

	if (bindedAddresses.count(address_zero) || bindedAddresses.count(address)) {
		// std::cout << "FOUND OVERLAP!" << std::endl;
		return -1;
	}

	AzocketKey key(sockfd, pid);

	azocketKeyToAddrInfo[key] = addr_info;
	azocketKeyToAzocket[key].addressKey.source = address;

	bindedAddresses.insert(address);

	// std::cout << "Successful binding of " << address.ip << " " << address.port << "\n";

	return 0;
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
	// std::cout << "sockfd = " << sockfd << std::endl; 

	AzocketKey key(sockfd, pid);
	if (!azocketKeys.count(key) || azocketKeyToAddrInfo.count(key)) {
		// std::cout << "Something wrong here..." << std::endl;
		// std::cout << azocketKeyToAddrInfo.count(key) << std::endl;

		Address address(azocketKeyToAddrInfo[key]);
		// std::cout << address.ip << " " << address.port << std::endl;

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
	std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
	uint16_t local_port = std::uniform_int_distribution<uint16_t>(1025, UINT16_MAX)(rng);

	uint32_t local_ip = 0;
	int index = this->getHost()->getRoutingTable((uint8_t *) &dest_ip);
	this->getHost()->getIPAddr((uint8_t *) &local_ip, index);

	local_ip = ntohl(local_ip);

	// std::cout << "implicit binding to -> " << local_ip << " " << local_port << "\n";
	// std::cout << Address(local_ip, local_port) << std::endl;

	AddrInfo addr_info(Address(local_ip, local_port));

	while (_syscall_bind(sockfd, pid, &addr_info.addr, addr_info.addrlen) != 0){
		local_port = std::uniform_int_distribution<uint16_t>(1025, UINT16_MAX)(rng);
		addr_info = AddrInfo(Address(local_ip, local_port));
	}
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen) {
	AzocketKey key(sockfd, pid);
	Azocket &azocket = azocketKeyToAzocket[key];
	// std::cout << "Called connect on (" << key.sockfd << ", " << key.pid << ")\n";

	Address dest_address(AddrInfo(*addr, addrlen));
	if (!azocketKeyToAddrInfo.count(key)){
		implicit_bind(sockfd, pid, dest_address.ip);
	}

	AddressKey &address_key = azocket.addressKey;
	address_key.dest = dest_address;

	// std::cout << "Implicitly created a socket with AddressKey = ([" << address_key.source.ip << ", " << address_key.source.port << "], [" << address_key.dest.ip << ", " << address_key.dest.port << "])\n";
	addressKeyToAzocketKey[address_key] = key;

	dispatchPacket(azocket, TH_SYN);

	azocket.syscall_id = syscallUUID;
	azocket.state = TCP_SYN_SENT;

	// std::cout << "SYNSENT from " << address_key.source.ip << " to " << address_key.dest.ip << "\n";
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog) {
	AzocketKey key(sockfd, pid);
	Azocket &azocket = azocketKeyToAzocket[key];

	azocket.listenControl.backlog = backlog;
	azocket.state = TCP_LISTEN;

	listenAddressToAzocketKey[azocket.addressKey.source] = key;

	// std::cout << "Listening on (" << sockfd << ", " << pid << "; ip = " << azocket.addressKey.source.ip << ", port = " << azocket.addressKey.source.port << ") with backlog = " << backlog << "\n";
	// std::cout << "No remote address should be set, checking: (" << azocket.addressKey.dest.ip << ", " << azocket.addressKey.dest.port << ")\n";

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	AzocketKey key(sockfd, pid);
	Azocket &azocket = azocketKeyToAzocket[key];

	if (azocket.state != TCP_LISTEN) {
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	// std::cout << "Accept called for " << sockfd << ", " << pid << std::endl;

	std::vector<int> &child_sockfds = azocket.listenControl.child_sockfds;
	auto it = std::find_if(child_sockfds.begin(), child_sockfds.end(), [&](int child_sockfd) {
		AzocketKey child_key(child_sockfd, pid);
		return azocketKeyToAzocket[child_key].state == TCP_ESTABLISHED;
	});
	if (it != child_sockfds.end()) {
		int child_sockfd = *it;
		child_sockfds.erase(it);

		_syscall_getpeername(child_sockfd, pid, addr, addrlen);

		// sockaddr_in addr_in = *((sockaddr_in *) addr);
		// std::cout << "(1) Triple checking the address: " << addr_in.sin_addr.s_addr << " " << addr_in.sin_port << "\n";
		// std::cout << "(2) Triple checking the address: " << ntohl(addr_in.sin_addr.s_addr) << " " << ntohs(addr_in.sin_port) << "\n";

		// Address address(AddrInfo(*addr, *addrlen));
		// std::cout << "(3) Triple checking the address -> " << address.ip << " " << address.port << "\n";

		// std::cout << "Accept returns " << child_sockfd << "\n";
		this->returnSystemCall(syscallUUID, child_sockfd);
		return;
	}

	// std::cout << "Accept blocked\n";
	azocket.acceptControl.addr = addr;
	azocket.acceptControl.addrlen = addrlen;
	azocket.acceptControl.blocked = true;
	azocket.acceptControl.syscall_id = syscallUUID;
}

void TCPAssignment::_syscall_getpeername(int sockfd, int pid, struct sockaddr *addr, socklen_t* addrlen) {
	AzocketKey key(sockfd, pid);
	
	Address &dest = azocketKeyToAzocket[key].addressKey.dest;
	// std::cout << "For " << sockfd << ", " << pid << " dest is " << dest.ip << ", " << dest.port << std::endl;

	AddrInfo addr_info(dest);
	*addr = addr_info.addr;
	*addrlen = addr_info.addrlen;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t* addrlen) {
	_syscall_getpeername(sockfd, pid, addr, addrlen);
	this->returnSystemCall(syscallUUID, 0);
}

Packet* TCPAssignment::makePacket(struct Azocket &azocket, uint8_t type) {
	// std::cout << "Making packet of type " << type;
	// std::cout << " and sending from " << azocket.addressKey.source;
	// std::cout << " to " << azocket.addressKey.dest << "\n";

	Packet *packet = this->allocatePacket(54);

	AddressKey address_key = azocket.addressKey;
	address_key.toNetwork();

	uint32_t seq_num = htonl(azocket.seq_num);

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

	uint16_t window_size = htons(51200);
	packet->writeData(14 + 20 + 14, &window_size, 2);

	size_t tcp_len = 20;
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
		// this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		// this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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

bool TCPAssignment::readPacket(Packet *packet, uint8_t &flags, AddressKey &address_key, uint32_t &seq_num, uint32_t &ack_num) {
	packet->readData(14 + 20 + 13, &flags, 1);
	packet->readData(14 + 12, &address_key.dest.ip, 4);
	packet->readData(14 + 16, &address_key.source.ip, 4);
	packet->readData(14 + 20 + 0, &address_key.dest.port, 2);
	packet->readData(14 + 20 + 2, &address_key.source.port, 2);
	packet->readData(14 + 20 + 4, &seq_num, 4);
	packet->readData(14 + 20 + 8, &ack_num, 4);

	uint16_t given_checksum = 0;
	packet->readData(14 + 20 + 16, &given_checksum, 2);

	uint16_t null_checksum = 0;
	packet->writeData(14 + 20 + 16, &null_checksum, 2);

	size_t tcp_len = 20;
	uint8_t *tcp_seg = (uint8_t *) malloc(tcp_len);
	packet->readData(14 + 20, tcp_seg, tcp_len);

	freePacket(packet);

	uint16_t checksum = htons(~NetworkUtil::tcp_sum(address_key.dest.ip, address_key.source.ip, tcp_seg, tcp_len));

	address_key.toHost();
	seq_num = ntohl(seq_num);
	ack_num = ntohl(ack_num);

	return checksum == given_checksum;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet *packet) {
	uint8_t flags = 0;
	AddressKey address_key;
	uint32_t seq_num = 0;
	uint32_t ack_num = 0;

	if (!readPacket(packet, flags, address_key, seq_num, ack_num)) {
		return;
	}

	// std::cout << "Packet came to me (" << address_key.source.ip << ", " << address_key.source.port << ") from (" << address_key.dest.ip << ", " << address_key.dest.port << ")\n";

	switch (flags) {
		case TH_FIN: {
			// std::cout << "FIN packet" << std::endl;
			break;
		}
		case TH_FIN | TH_ACK: {
			// std::cout << "FINACK packet" << std::endl;
			break;
		}
		case TH_SYN: {
			Address source = address_key.source;
			Address source_zero = source;
			source_zero.ip = 0;

			// std::cout << "source vs source_zero: " << listenAddressToAzocketKey.count(source) << " " << listenAddressToAzocketKey.count(source_zero) << std::endl;

			AzocketKey &key = listenAddressToAzocketKey.count(source_zero) ? listenAddressToAzocketKey[source_zero] : listenAddressToAzocketKey[source]; // assumption that such listening socket exists
			Azocket &azocket = azocketKeyToAzocket[key];

			// std::cout << "SYN: " << key.sockfd << " " << key.pid << " " << azocket.listenControl.backlog << std::endl;

			if (azocket.state != TCP_LISTEN) {
				AzocketKey &key = addressKeyToAzocketKey[address_key];
				Azocket &azocket = azocketKeyToAzocket[key];
				AddressKey &new_address_key = azocket.addressKey;

				new_address_key = address_key;
				azocket.ack_num = seq_num + 1;
				addressKeyToAzocketKey[address_key] = key;
				dispatchPacket(azocket, TH_SYN | TH_ACK);
				azocket.state = TCP_SYN_RECV;
				break;

				// std::cout << "SYN Packet Denied\n";
				// break;
			}
			if (azocket.listenControl.backlog == 0){
				// std::cout << "SYN The main concern for (1) that we considered is:Packet Denied\n";
				break;
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

			// std::cout << "SYN: " << seq_num << " " << ack_num << " " << new_azocket.seq_num << "\n";

			addressKeyToAzocketKey[new_address_key] = new_key;
			dispatchPacket(new_azocket, TH_SYN | TH_ACK);

			new_azocket.state = TCP_SYN_RECV;
			break;
		}
		case TH_SYN | TH_ACK: { // we need retransmission here in the future
			AzocketKey &key = addressKeyToAzocketKey[address_key];
			Azocket &azocket = azocketKeyToAzocket[key];

			// std::cout << "SYNACK: " << key.sockfd << " " << ack_num << " " << azocketKeyToAzocket[key].seq_num << "\n";
			if (ack_num != azocket.seq_num + 1) {
				// Not doing this call below because it could be just erroneous packet...
				// Hope that the destination host will send us the right packet.
				// this->returnSystemCall(azocketKeyToAzocket[sockfd].syscall_id, -1);
				// std::cout << "SYNACK Packet Denied\n";
				break;
			}
			
			azocket.ack_num = seq_num + 1;
			azocket.seq_num++;
			dispatchPacket(azocket, TH_ACK);

			azocket.state = TCP_ESTABLISHED;

			this->returnSystemCall(azocket.syscall_id, 0);
			break;
		}
		case TH_ACK: {
			AzocketKey &key = addressKeyToAzocketKey[address_key];
			Azocket &azocket = azocketKeyToAzocket[key];

			// std::cout << "ACK: " << key.sockfd << " " << ack_num << " " << azocketKeyToAzocket[key].seq_num << "\n";
			if (ack_num != azocket.seq_num + 1 || azocket.state != TCP_SYN_RECV) {
				// Not doing this call below because it could be just erroneous packet...
				// Hope that the destination host will send us the right packet.
				// this->returnSystemCall(azocketKeyToAzocket[sockfd].syscall_id, -1);
				// std::cout << "ACK Packet Denied\n";
				break;
			}

			azocket.state = TCP_ESTABLISHED;

			int parent_sockfd = azocket.listenControl.parent_sockfd;
			AzocketKey parent_key = {parent_sockfd, key.pid};
			Azocket &parent_azocket = azocketKeyToAzocket[parent_key];
			parent_azocket.listenControl.backlog++;

			// std::cout << "ACK: " << parent_sockfd << " " << key.pid << " " << parent_azocket.listenControl.backlog << std::endl;

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
				this->returnSystemCall(parent_azocket.acceptControl.syscall_id, key.sockfd);
			}

			break;
		}
		default: {
			// std::cout << "Some other type of packet" << std::endl;
			break;
		}
	}
}

void TCPAssignment::timerCallback(void* payload) {

}
}