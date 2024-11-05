/*
* Cole McAnelly
* CSCE 463 - Dist. Network Systems
* Fall 2024
*/

#pragma once
#pragma pack(push, 1)	 // Set packing alignment to 1 byte

#include "pch.h"

#include "DnsConstants.h"


class Packet
{
	std::vector<std::byte> bytes;

public:
	Packet(std::vector<std::byte>&& _bytes) : bytes(std::move(_bytes)) {}

	constexpr const std::byte* data() const { return bytes.data(); }
	constexpr const size_t size() const { return bytes.size(); }

	void parse();

	const uint16_t id() const { return ntohs(((FixedDNSheader*)bytes.data())->id); }
	const uint16_t flags() const { return ntohs(((FixedDNSheader*)bytes.data())->flags); }
	const uint16_t n_questions() const { return ntohs(((FixedDNSheader*)bytes.data())->n_questions); }
	const uint16_t n_answers() const { return ntohs(((FixedDNSheader*)bytes.data())->n_answers); }
	const uint16_t n_authority() const { return ntohs(((FixedDNSheader*)bytes.data())->n_authority); }
	const uint16_t n_additional() const { return ntohs(((FixedDNSheader*)bytes.data())->n_additional); }

	bool id_valid_reponse(const Packet& reponse) {
		if (auto rcode = reponse.flags() & 0x0F) throw ParseError("Rcode = " + std::to_string(rcode));
		else printf("  succeeded with Rcode = 0\n");

		if (this->id() != reponse.id()) {
			printf("  ++ invalid reply: TXID mismatch, sent 0x%.4X, received 0x%.4X", this->id(), reponse.id());
			return false;
		}
		/*if (this->n_questions() != reponse.n_questions()) {
			printf("  ++ invalid reply: N Questions mismatch, sent %hu, received %hu", this->n_questions(), reponse.n_questions());
			return false;
		}*/
		return true;
	}


	struct ParseError : public std::runtime_error {
		explicit ParseError(const std::string& msg = "") : std::runtime_error("failed with " + msg) {}
	};

	class Builder {
		std::vector<std::byte> bytes;
		Builder(size_t packet_len);
		Builder(const std::string& host);
		Builder(const std::string& host, DnsType type);

	public:
		static Builder from(const std::string& host);

		inline Builder& id(uint16_t _id) {
			printf(", TXID 0x%.4X\n", _id);
			((FixedDNSheader*)bytes.data())->id = htons(_id);
			return *this;
		}
		inline Builder& flags(uint16_t _flags) {
			((FixedDNSheader*)bytes.data())->flags = htons(_flags);
			return *this;
		}
		inline Builder& n_questions(uint16_t _questions) {
			((FixedDNSheader*)bytes.data())->n_questions = htons(_questions);
			return *this;
		}
		inline Builder& n_answers(uint16_t _answers) {
			((FixedDNSheader*)bytes.data())->n_answers = htons(_answers);
			return *this;
		}
		inline Builder& n_authority(uint16_t _authority) {
			((FixedDNSheader*)bytes.data())->n_authority = htons(_authority);
			return *this;
		}
		inline Builder& n_additional(uint16_t _additional) {
			((FixedDNSheader*)bytes.data())->n_additional = htons(_additional);
			return *this;
		}
		inline Packet build() { return Packet(std::move(bytes)); }
	};

	struct FixedDNSheader {
		uint16_t id;
		uint16_t flags;
		uint16_t n_questions;
		uint16_t n_answers;
		uint16_t n_authority;
		uint16_t n_additional;
	};

private:
	constexpr inline bool out_of_bounds(std::byte* ptr) { return ptr >= bytes.data() + bytes.size(); }
	constexpr inline size_t lower_14(std::byte*& ptr) {
		if (out_of_bounds(ptr + 1)) throw MaliciousError("  ++ invalid record: truncated jump offset");
		return (((size_t)*ptr++ & 0x3F) << 8) + (size_t)*ptr++;
	}

	const std::string decode_ip_url(size_t off, size_t n_jumps = 0) {
		if (off < sizeof(FixedDNSheader)) throw MaliciousError("  ++ invalid record: jump into fixed DNS header");
		return decode_ip_url(&bytes.data()[off], n_jumps);
	}
	const std::string decode_ip_url(std::byte*&& iter, size_t n_jumps = 0) { return decode_ip_url(iter, n_jumps); }
	inline const std::string decode_ip_url(std::byte*& iter, size_t n_jumps = 0);

	std::byte* parse_question(std::byte* iter);
	std::byte* parse_answer(std::byte* iter);

	struct QueryHeader {
		uint16_t _type;
		uint16_t _class;
	};
	struct AnswerHeader {
		uint16_t _type;
		uint16_t _class;
		uint32_t _ttl;
		uint16_t _len;
	};
	
};

#pragma pack(pop)	// Restore default packing alignment

