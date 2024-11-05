/*
* Cole McAnelly
* CSCE 463 - Dist. Network Systems
* Fall 2024
*/

#include "pch.h"
#include "Packet.h"


void Packet::parse()
{
	std::byte* iter = (std::byte*)&((FixedDNSheader*)bytes.data())[1];

	size_t min_bytes = 0;

	if (auto questions = n_questions()) {
		printf("  ------------ [questions] ----------\n");
		min_bytes += questions * sizeof(QueryHeader);
		if (min_bytes > size()) throw MaliciousError("  ++ invalid section: not enough records");
		for (int _ = 0; _ < questions; _++) {
			if (out_of_bounds(iter)) throw MaliciousError("  ++ invalid record: RR value length stretches the answer beyond packet");
			iter = parse_question(iter);
		}
	}
	if (auto answers = n_answers()) {
		printf("  ------------ [answers] ------------\n");
		min_bytes += answers * sizeof(AnswerHeader);
		if (min_bytes > size()) throw MaliciousError("  ++ invalid section: not enough records");
		for (int _ = 0; _ < answers; _++) {
			if (out_of_bounds(iter)) throw MaliciousError("  ++ invalid record: RR value length stretches the answer beyond packet");
			iter = parse_answer(iter);
		}
	}
	if (auto authority = n_authority()) {
		printf("  ------------ [authority] ----------\n");
		min_bytes += authority * sizeof(AnswerHeader);
		if (min_bytes > size()) throw MaliciousError("  ++ invalid section: not enough records");
		for (int _ = 0; _ < authority; _++) {
			if (out_of_bounds(iter)) throw MaliciousError("  ++ invalid record: RR value length stretches the answer beyond packet");
			iter = parse_answer(iter);
		}
	}
	if (auto additional = n_additional()) {
		printf("  ------------ [additional] ---------\n");
		min_bytes += additional * sizeof(AnswerHeader);
		if (min_bytes > size()) throw MaliciousError("  ++ invalid section: not enough records");
		for (int _ = 0; _ < additional; _++) {
			if (out_of_bounds(iter)) throw MaliciousError("  ++ invalid record: RR value length stretches the answer beyond packet");
			iter = parse_answer(iter);
		}
	}
}

std::byte* Packet::parse_question(std::byte* iter) {
	const std::string url = decode_ip_url(iter);
	QueryHeader* q = (QueryHeader*)iter;
	printf("\t%s type %hu class %hu\n", url.c_str(), ntohs(q->_type), ntohs(q->_class));
	return (std::byte*)++q;
}

std::byte* Packet::parse_answer(std::byte* iter) {
	const std::string url = decode_ip_url(iter);

	if (out_of_bounds(iter + sizeof(AnswerHeader))) throw MaliciousError("  ++ invalid record: truncated RR answer header");
	AnswerHeader* a = (AnswerHeader*)iter;
	
	switch (auto type = (DnsType)ntohs(a->_type))
	{
	case DnsType::DNS_A: {
		struct in_addr addr;
		addr.s_addr = ntohl(*(uint32_t*)&a[1]);
		printf("\t%s A %s TTL = %u\n", url.c_str(), inet_ntoa(addr), ntohl(a->_ttl));
		break;
	} case DnsType::DNS_NS: {
		const std::string rdata_text = decode_ip_url((std::byte*)&a[1]);
		printf("\t%s NS %s TTL = %u\n", url.c_str(), rdata_text.c_str(), ntohl(a->_ttl));
		break;
	} case DnsType::DNS_CNAME: {
		const std::string rdata_text = decode_ip_url((std::byte*)&a[1]);
		printf("\t%s CNAME %s TTL = %u\n", url.c_str(), rdata_text.c_str(), ntohl(a->_ttl));
		break;
	} case DnsType::DNS_PTR: {
		const std::string rdata_text = decode_ip_url((std::byte*)&a[1]);
		printf("\t%s PTR %s TTL = %u\n", url.c_str(), rdata_text.c_str(), ntohl(a->_ttl));
		break;
	} default: break;
	}

	return ((std::byte*)&a[1]) + ntohs(a->_len);
}

const std::string Packet::decode_ip_url(std::byte*& iter, size_t n_jumps) {
	if (n_jumps > MAX_DNS_SIZE / 2) throw MaliciousError("  ++ invalid record: jump loop");
	if (out_of_bounds(iter)) throw MaliciousError("  ++ invalid record: jump beyond packet boundary");
	char* url_start = (char*)iter;
	uint8_t len = 0;
	for (len = (uint8_t)*iter; len != 0 && !(len & 0xC0); iter += len + 1, len = (uint8_t)*iter) {
		if (out_of_bounds(iter)) throw MaliciousError("  ++ invalid record: truncated name");
		*(char*)iter = '.';
	}

	if (url_start == (char*)iter) {
		if (len == 0) return "";
		if (len & 0xC0) return decode_ip_url(lower_14(iter), ++n_jumps);
	}

	*url_start = (char*)iter - url_start - 1;
	if (len == 0) return std::string(++url_start, (char*)iter++);
	if (len & 0xC0) {
		return std::string(++url_start, (char*)iter) + decode_ip_url(lower_14(iter), ++n_jumps);
	}
}



Packet::Builder::Builder(size_t packet_len)
	: bytes(packet_len, std::byte{ 0 })
{}

// Question Constructor
Packet::Builder::Builder(const std::string& host)
	: Builder(sizeof(FixedDNSheader) + host.size() + 2 + sizeof(QueryHeader))
{
	std::byte* query_start = (std::byte*)&((FixedDNSheader*)bytes.data())[1];
	memcpy(query_start + 1, host.c_str(), host.size());
	query_start[host.size() + 2] = std::byte{ 0 };

	size_t pos = 0;
	for (
		size_t next = host.find('.');
		next != std::string::npos;
		pos = ++next, next = host.find('.', pos)
		) query_start[pos] = std::byte{ uint8_t(next - pos) };
	query_start[pos] = std::byte{ uint8_t(host.size() - pos) };

}

// Query param Constructor
Packet::Builder::Builder(const std::string& host, DnsType type)
	: Builder(host)
{
	printf("Query\t: %s, type %hu", host.c_str(), (uint16_t)type);
	QueryHeader* q = (QueryHeader*)(bytes.data() + bytes.size() - sizeof(QueryHeader));
	q->_type = htons((uint16_t)type);
	q->_class = htons((uint16_t)DnsClass::DNS_INET);
}


Packet::Builder Packet::Builder::from(const std::string& host)
{
	printf("Lookup\t: %s\n", host.c_str());
	if (inet_addr(host.c_str()) == INADDR_NONE)
		return Builder(host, DnsType::DNS_A);
	else
		return Builder(host + ".in-addr.arpa", DnsType::DNS_PTR);
}
