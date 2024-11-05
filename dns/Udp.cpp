/*
* Cole McAnelly
* CSCE 463 - Dist. Network Systems
* Fall 2024
*/

#include "pch.h"
#include "Udp.h"


Udp::Udp(const std::string& server_ip)
	: sock(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))
	, server{0}
{
	if (sock == INVALID_SOCKET) throw WinSock::FatalError("couldn't create socket!");
	struct sockaddr_in local { 0 };

	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(0);

	int err = bind(this->sock, (struct sockaddr*)&local, sizeof(struct sockaddr_in));
	if (err == SOCKET_ERROR) throw WinSock::FatalError("Failed to bind");

	// init the server to connect to
	printf("Server\t: %s\n", server_ip.c_str());
	server.sin_family = AF_INET;
	server.sin_port = htons(53);
	server.sin_addr.s_addr = inet_addr(server_ip.c_str());
}

Packet Udp::query(const Packet& p) const {
	printf("********************************\n");
	bool got_response = false;
	std::vector<std::byte> buff(MAX_DNS_SIZE, std::byte{ 0 });

	for (size_t attempt = 0; attempt < MAX_ATTEMPTS  && !got_response; attempt++)
	{
		printf("Attempt %llu with %llu bytes... ", attempt, p.size());
		send(p);
		got_response = receive(buff);
	}
	if (!got_response) throw Udp::Error();
	/*for (std::byte& b : buff) printf("0x%.2X ", b);*/
	return Packet(std::move(buff));
}


void Udp::send(const Packet& p) const {
	int err = sendto(this->sock, (const char*)p.data(), p.size(), NULL, (struct sockaddr*)&this->server, sizeof(struct sockaddr_in));
	if (err == SOCKET_ERROR) throw Udp::SocketError("sendto failed");
}

bool Udp::receive(std::vector<std::byte>& bytes) const {
	auto start = Time::now();
	fd_set fd;
	FD_ZERO(&fd);
	FD_SET(this->sock, &fd);
	// clear the set 
	// add your socket to the set 
	int err = select(0, &fd, NULL, NULL, &TIMEOUT);
	if (err < 0) throw Udp::SocketError("select failed");
	if (err == 0) {
		std::cout << "timeout in " << time_elapsed<milliseconds>(start) << "\n";
		return false;
	}

	struct sockaddr_in responder;
	int reponder_addr_size = sizeof(struct sockaddr_in);

	int num_bytes = recvfrom(this->sock, (char*)bytes.data(), bytes.size(), NULL, (SOCKADDR*)&responder, &reponder_addr_size);

	if (num_bytes < 0) throw Udp::SocketError("in recvfrom");
	if (num_bytes == 0) throw Udp::Error("connection closed");

	if (responder.sin_addr.s_addr != server.sin_addr.s_addr
		|| responder.sin_port != server.sin_port) throw Udp::Error("bogus reply"); // return false;

	bytes.resize(num_bytes);
	if (bytes.size() < sizeof(Packet::FixedDNSheader)) throw MaliciousError("\n  ++ invalid reply: packet smaller than fixed DNS header");
	std::cout << "response in " << time_elapsed<milliseconds>(start) << " with " << bytes.size() << " bytes\n";

	return true;
}