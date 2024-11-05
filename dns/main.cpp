// main.cpp : This file contains the 'main' function. Program execution begins and ends there.
/*
* Cole McAnelly
* CSCE 463 - Dist. Network Systems
* Fall 2024
*/

#include "pch.h"
#include <iostream>

#include "Packet.h"
#include "Udp.h"
#include "DnsConstants.h"

int main(int argc, char* argv[]) try {

	if (argc != 3) {
		printf(USAGE_INFO);
		exit(-1);
	}
	const char* lookup = argv[1];
	const char* server = argv[2];

	printf("\n\n");
	Packet req = Packet::Builder::from(lookup)
		.id(0x0024)
		.flags(DNS_QUERY | DNS_RD | DNS_STDQUERY)
		.n_questions(1)
		.n_answers(0)
		.n_authority(0)
		.n_additional(0)
		.build();

	Packet res = Udp(server).query(req);
	printf("  TXID 0x%.4X, flags 0x%.4X, questions %hu, answers %hu, authority %hu, additional %hu\n",
		res.id(),
		res.flags(),
		res.n_questions(),
		res.n_answers(),
		res.n_authority(),
		res.n_additional()
	);
	if (!req.id_valid_reponse(res)) throw MaliciousError();

	res.parse();

}
catch (const Packet::ParseError& e) { printf("  %s\n", e.what()); }
catch (const std::runtime_error& e) { printf("%s\n", e.what()); }