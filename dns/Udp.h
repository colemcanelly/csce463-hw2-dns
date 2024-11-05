/*
* Cole McAnelly
* CSCE 463 - Dist. Network Systems
* Fall 2024
*/

#pragma once


#include "pch.h"

#include "WinSock.h"
#include "Packet.h"

class Udp : WinSock
{
	SOCKET sock;
	struct sockaddr_in server;

public:
	Udp(const std::string& server_ip);

	Packet query(const Packet& p) const;

	struct Error : public std::runtime_error {
		explicit Error() : std::runtime_error("") {}
		explicit Error(const std::string& msg) : std::runtime_error("failed with " + msg) {}
	};

	struct SocketError : public WinSock::Error {
		explicit SocketError(const std::string& msg = "") : WinSock::Error(msg) {}
	};

private:

	static constexpr struct timeval TIMEOUT{ .tv_sec = 10, .tv_usec = 0 };
	static constexpr size_t MAX_ATTEMPTS = 3;

	inline void send(const Packet& p) const;
	inline bool receive(std::vector<std::byte>& bytes) const;
};

