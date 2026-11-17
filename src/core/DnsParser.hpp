#pragma once
// Full DNS wire-format parser med komprimeringsstøtte (RFC 1035).

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace aifw {

struct DnsQuestion {
    std::string name;
    uint16_t type{0};
    uint16_t cls{0};
};

struct DnsRecord {
    std::string name;
    uint16_t type{0};
    uint16_t cls{0};
    uint32_t ttl{0};
    std::vector<uint8_t> rdata;
    std::string rdataStr;  // Parsed for common types
};

struct DnsMessage {
    uint16_t id{0};
    uint16_t flags{0};
    uint8_t rcode{0};
    std::vector<DnsQuestion> questions;
    std::vector<DnsRecord> answers;
    std::vector<DnsRecord> authorities;
    std::vector<DnsRecord> additionals;
};

class DnsParser {
public:
    // Parse DNS-melding
    static std::optional<DnsMessage> parse(const uint8_t* data, size_t len);

    // Bygg DNS-spørring
    static std::vector<uint8_t> buildQuery(const std::string& name, uint16_t type, uint16_t id = 0);

private:
    static std::optional<std::string> parseName(const uint8_t* data, size_t len,
        size_t& pos, int depth = 0);
    static std::string parseRdata(uint16_t type, const uint8_t* rdata, size_t rdlen,
        const uint8_t* msg, size_t msgLen);
    static void writeName(std::vector<uint8_t>& out, const std::string& name);
};

} // namespace aifw
