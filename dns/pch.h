// pch.h: This is a precompiled header file.
/*
* Cole McAnelly
* CSCE 463 - Dist. Network Systems
* Fall 2024
*/

// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include <cstdint>
#include <cstddef>
#include <string>
#include <iostream>
#include <memory>
#include <optional>
#include <limits>
#include <exception>
#include <chrono>
#include <set>
#include <mutex>
#include <functional>

#define NOMINMAX
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

// Timing operations
using Time = std::chrono::high_resolution_clock;
using seconds = std::chrono::seconds;
using milliseconds = std::chrono::milliseconds;

template <typename T>
constexpr T time_elapsed(Time::time_point begin) { return std::chrono::duration_cast<T>(Time::now() - begin); }

struct MaliciousError : public std::runtime_error {
	explicit MaliciousError(const std::string& msg = "") : std::runtime_error(msg) {}
};


#define USAGE_INFO "\n\nUsage: dns <hostname> <DNS Server IP>\n"

#endif //PCH_H