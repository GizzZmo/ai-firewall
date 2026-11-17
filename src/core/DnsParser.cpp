#include "DnsParser.hpp"

#include <cstring>
#include <sstream>

namespace aifw {

constexpr int kMaxCompressionDepth = 16;

std::optional<std::string> DnsParser::parseName(const uint8_t* data, size_t len,
    size_t& pos, int depth) {
    if (depth > kMaxCompressionDepth) return std::nullopt;

    std::string name;
    bool jumped = false;
    size_t jumpPos = pos;

    while (pos < len) {
        uint8_t labelLen = data[pos];

        if (labelLen == 0) {
            pos++;
            break;
        }

        // Compression pointer (top 2 bits set)
        if ((labelLen & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return std::nullopt;
            uint16_t offset = ((labelLen & 0x3F) << 8) | data[pos + 1];
            if (offset >= len) return std::nullopt;

            if (!jumped) {
                jumpPos = pos + 2;
                jumped = true;
            }

            size_t ptrPos = offset;
            auto suffix = parseName(data, len, ptrPos, depth + 1);
            if (!suffix) return std::nullopt;

            if (!name.empty() && !suffix->empty()) name += ".";
            name += *suffix;
            break;
        }

        // Regular label
        if (labelLen > 63) return std::nullopt;  // Invalid
        pos++;
        if (pos + labelLen > len) return std::nullopt;

        if (!name.empty()) name += ".";
        name.append(reinterpret_cast<const char*>(data + pos), labelLen);
        pos += labelLen;
    }

    if (jumped) pos = jumpPos;
    return name;
}

std::string DnsParser::parseRdata(uint16_t type, const uint8_t* rdata, size_t rdlen,
    const uint8_t* msg, size_t msgLen) {
    switch (type) {
        case 1:  // A
            if (rdlen == 4) {
                char buf[16];
                snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                    rdata[0], rdata[1], rdata[2], rdata[3]);
                return buf;
            }
            break;
        case 28:  // AAAA
            if (rdlen == 16) {
                char buf[40];
                snprintf(buf, sizeof(buf),
                    "%x:%x:%x:%x:%x:%x:%x:%x",
                    (rdata[0] << 8) | rdata[1], (rdata[2] << 8) | rdata[3],
                    (rdata[4] << 8) | rdata[5], (rdata[6] << 8) | rdata[7],
                    (rdata[8] << 8) | rdata[9], (rdata[10] << 8) | rdata[11],
                    (rdata[12] << 8) | rdata[13], (rdata[14] << 8) | rdata[15]);
                return buf;
            }
            break;
        case 12:  // PTR
        case 2:   // NS
        case 5:   // CNAME
            {
                size_t pos = static_cast<size_t>(rdata - msg);
                auto name = parseName(msg, msgLen, pos);
                return name.value_or("");
            }
        case 16:  // TXT
            if (rdlen > 0) {
                uint8_t txtLen = rdata[0];
                if (txtLen + 1 <= rdlen) {
                    return std::string(reinterpret_cast<const char*>(rdata + 1), txtLen);
                }
            }
            break;
    }
    return "";
}

std::optional<DnsMessage> DnsParser::parse(const uint8_t* data, size_t len) {
    if (len < 12) return std::nullopt;

    DnsMessage msg;
    msg.id = (data[0] << 8) | data[1];
    msg.flags = (data[2] << 8) | data[3];
    msg.rcode = data[3] & 0x0F;

    uint16_t qdcount = (data[4] << 8) | data[5];
    uint16_t ancount = (data[6] << 8) | data[7];
    uint16_t nscount = (data[8] << 8) | data[9];
    uint16_t arcount = (data[10] << 8) | data[11];

    size_t pos = 12;

    // Questions
    for (uint16_t i = 0; i < qdcount; ++i) {
        auto name = parseName(data, len, pos);
        if (!name || pos + 4 > len) return std::nullopt;

        DnsQuestion q;
        q.name = *name;
        q.type = (data[pos] << 8) | data[pos + 1];
        q.cls = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        msg.questions.push_back(std::move(q));
    }

    // Helper to parse records
    auto parseRecords = [&](uint16_t count, std::vector<DnsRecord>& out) -> bool {
        for (uint16_t i = 0; i < count; ++i) {
            auto name = parseName(data, len, pos);
            if (!name || pos + 10 > len) return false;

            DnsRecord r;
            r.name = *name;
            r.type = (data[pos] << 8) | data[pos + 1];
            r.cls = (data[pos + 2] << 8) | data[pos + 3];
            r.ttl = (data[pos + 4] << 24) | (data[pos + 5] << 16) |
                    (data[pos + 6] << 8) | data[pos + 7];
            uint16_t rdlen = (data[pos + 8] << 8) | data[pos + 9];
            pos += 10;

            if (pos + rdlen > len) return false;
            r.rdata.assign(data + pos, data + pos + rdlen);
            r.rdataStr = parseRdata(r.type, data + pos, rdlen, data, len);
            pos += rdlen;

            out.push_back(std::move(r));
        }
        return true;
    };

    if (!parseRecords(ancount, msg.answers)) return std::nullopt;
    if (!parseRecords(nscount, msg.authorities)) return std::nullopt;
    if (!parseRecords(arcount, msg.additionals)) return std::nullopt;

    return msg;
}

void DnsParser::writeName(std::vector<uint8_t>& out, const std::string& name) {
    std::istringstream iss(name);
    std::string label;
    while (std::getline(iss, label, '.')) {
        if (label.empty()) continue;
        if (label.size() > 63) label.resize(63);
        out.push_back(static_cast<uint8_t>(label.size()));
        out.insert(out.end(), label.begin(), label.end());
    }
    out.push_back(0);
}

std::vector<uint8_t> DnsParser::buildQuery(const std::string& name, uint16_t type, uint16_t id) {
    std::vector<uint8_t> query;

    // Header
    query.push_back(id >> 8);
    query.push_back(id & 0xFF);
    query.push_back(0x01);  // RD=1
    query.push_back(0x00);
    query.push_back(0x00);  // QDCOUNT=1
    query.push_back(0x01);
    query.push_back(0x00);  // ANCOUNT=0
    query.push_back(0x00);
    query.push_back(0x00);  // NSCOUNT=0
    query.push_back(0x00);
    query.push_back(0x00);  // ARCOUNT=0
    query.push_back(0x00);

    // Question
    writeName(query, name);
    query.push_back(type >> 8);
    query.push_back(type & 0xFF);
    query.push_back(0x00);  // CLASS=IN
    query.push_back(0x01);

    return query;
}

} // namespace aifw
