/*
* Cole McAnelly
* CSCE 463 - Dist. Network Systems
* Fall 2024
*/

#pragma once

#include "pch.h"

// Error hierarchy for fatal and recoverable errors (fatal errors are higher, and therefore won't be caught until later
/* Exception hierarchy
fatal_socket error
|-- fatal_winsock error
|   '-- winsock error
'-- socket error
*/

// RAII for winsock DLL
class WinSock {
public:
	WinSock()
	{
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData)) throw WinSock::FatalError("WSAStartup");
	}

	~WinSock() { WSACleanup(); }

	struct FatalError : public std::runtime_error {
		explicit FatalError(const std::string& msg = "") : std::runtime_error("socket error " + std::to_string(h_errno) + " " + msg) {}
	};

	struct Error : public FatalError {
		explicit Error(const std::string& msg = "") : FatalError(msg) {}
	};

	static inline uint32_t dns(const std::string& hostname) {
		// Got info from reading inaddr.h
		std::cout << "\tDoing DNS... ";
		auto start = Time::now();
		in_addr ip;
		ip.s_addr = inet_addr(hostname.c_str());
		if (ip.s_addr == INADDR_NONE) {
			hostent* host = gethostbyname(hostname.c_str());
			if (host == NULL) throw WinSock::Error("(DNS failure)");;
			ip.s_addr = *reinterpret_cast<uint32_t*>(host->h_addr);
		}
		std::cout << "done in " << time_elapsed<milliseconds>(start) << ", found " << inet_ntoa(ip) << "\n";
		return ip.s_addr;
	}
};
