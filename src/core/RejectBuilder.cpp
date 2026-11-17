#include "RejectBuilder.hpp"

#include <algorithm>

namespace aifw {
namespace {

void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v >> 8);
    b[off + 1] = static_cast<std::uint8_t>(v);
}

void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    b[off] = static_cast<std::uint8_t>(v >> 24);
    b[off + 1] = static_cast<std::uint8_t>(v >> 16);
    b[off + 2] = static_cast<std::uint8_t>(v >> 8);
    b[off + 3] = static_cast<std::uint8_t>(v);
}

std::uint32_t addWords(const std::uint8_t* p, std::size_t n, std::uint32_t sum) noexcept {
    while (n > 1) {
        sum += (static_cast<std::uint32_t>(p[0]) << 8) | p[1];
        p += 2;
        n -= 2;
    }
    if (n == 1) sum += static_cast<std::uint32_t>(p[0]) << 8;
    return sum;
}

std::uint16_t finish(std::uint32_t sum) noexcept {
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

void writeAddr(std::vector<std::uint8_t>& b, std::size_t off, const IpAddress& ip) {
    const std::size_t n = ip.version == 6 ? 16 : 4;
    std::copy_n(ip.bytes.begin(), n, b.begin() + static_cast<std::ptrdiff_t>(off));
}

std::uint16_t ipv4Checksum(const std::uint8_t* hdr) noexcept {
    return finish(addWords(hdr, 20, 0));
}

void checksumTransport(std::vector<std::uint8_t>& pkt, std::size_t l4, std::uint8_t proto, bool v6,
                       std::size_t csumOff, bool pseudo) {
    const std::size_t segLen = pkt.size() - l4;
    std::uint32_t sum = 0;
    if (pseudo && !v6) {
        sum = addWords(pkt.data() + 12, 8, 0);
        sum += proto;
        sum += static_cast<std::uint32_t>(segLen);
    } else if (pseudo && v6) {
        sum = addWords(pkt.data() + 8, 32, 0);
        sum += static_cast<std::uint32_t>(segLen >> 16);
        sum += static_cast<std::uint32_t>(segLen & 0xFFFFu);
        sum += proto;
    }
    put16(pkt, l4 + csumOff, 0);
    put16(pkt, l4 + csumOff, finish(addWords(pkt.data() + l4, segLen, sum)));
}

std::vector<std::uint8_t> ipv4Header(const IpAddress& src, const IpAddress& dst, std::uint8_t proto,
                                     std::uint16_t total) {
    std::vector<std::uint8_t> p(20, 0);
    p[0] = 0x45;
    put16(p, 2, total);
    p[8] = 64;
    p[9] = proto;
    writeAddr(p, 12, src);
    writeAddr(p, 16, dst);
    put16(p, 10, ipv4Checksum(p.data()));
    return p;
}

std::vector<std::uint8_t> ipv6Header(const IpAddress& src, const IpAddress& dst, std::uint8_t next,
                                     std::uint16_t payloadLen) {
    std::vector<std::uint8_t> p(40, 0);
    p[0] = 0x60;
    put16(p, 4, payloadLen);
    p[6] = next;
    p[7] = 64;
    writeAddr(p, 8, src);
    writeAddr(p, 24, dst);
    return p;
}

struct RstFields {
    std::uint32_t seq{0};
    std::uint32_t ack{0};
    std::uint8_t flags{tcpflags::RST};
};

RstFields rstFields(const PacketInfo& info) noexcept {
    const bool syn = (info.tcpFlags & tcpflags::SYN) != 0;
    const bool fin = (info.tcpFlags & tcpflags::FIN) != 0;
    const std::uint32_t seglen =
        static_cast<std::uint32_t>(info.payloadLength) + (syn ? 1u : 0u) + (fin ? 1u : 0u);
    RstFields r;
    if ((info.tcpFlags & tcpflags::ACK) != 0) {
        r.seq = info.tcpAck;
        r.flags = tcpflags::RST;
    } else {
        r.seq = 0;
        r.ack = info.tcpSeq + seglen;
        r.flags = static_cast<std::uint8_t>(tcpflags::RST | tcpflags::ACK);
    }
    return r;
}

std::vector<std::uint8_t> tcpSegment(std::uint16_t sp, std::uint16_t dp, const RstFields& r) {
    std::vector<std::uint8_t> t(20, 0);
    put16(t, 0, sp);
    put16(t, 2, dp);
    put32(t, 4, r.seq);
    put32(t, 8, r.ack);
    t[12] = 5 << 4;
    t[13] = r.flags;
    return t;
}

std::size_t quoteLength(const PacketInfo& info, std::span<const std::uint8_t> original) noexcept {
    if (info.srcIp.version == 4) {
        if (original.size() < 20) return 0;
        const std::size_t ihl = static_cast<std::size_t>(original[0] & 0x0F) * 4;
        if (ihl < 20 || ihl > original.size()) return 0;
        return std::min(original.size(), ihl + 8);
    }
    if (info.srcIp.version == 6) {
        if (original.size() < 40) return 0;
        // ICMPv6-pakken skal holde seg under IPv6 minimum-MTU (1280).
        return std::min(original.size(), static_cast<std::size_t>(1280 - 40 - 8));
    }
    return 0;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> buildTcpRst(const PacketInfo& info) {
    if (info.protocol != Protocol::TCP) return std::nullopt;
    if (info.srcIp.version != 4 && info.srcIp.version != 6) return std::nullopt;
    if (!info.srcIp.isValid() || !info.dstIp.isValid()) return std::nullopt;

    const auto fields = rstFields(info);
    // Svar til avsenderen: kilde er den opprinnelige destinasjonen.
    auto tcp = tcpSegment(info.dstPort, info.srcPort, fields);
    const bool v6 = info.srcIp.version == 6;
    std::vector<std::uint8_t> pkt = v6 ? ipv6Header(info.dstIp, info.srcIp, 6, static_cast<std::uint16_t>(tcp.size()))
                                       : ipv4Header(info.dstIp, info.srcIp, 6, static_cast<std::uint16_t>(20 + tcp.size()));
    const std::size_t l4 = pkt.size();
    pkt.insert(pkt.end(), tcp.begin(), tcp.end());
    checksumTransport(pkt, l4, 6, v6, 16, true);
    return pkt;
}

std::optional<std::vector<std::uint8_t>> buildPortUnreachable(const PacketInfo& info,
                                                             std::span<const std::uint8_t> original) {
    if (info.protocol != Protocol::UDP) return std::nullopt;
    const std::size_t quote = quoteLength(info, original);
    if (quote == 0) return std::nullopt;

    const bool v6 = info.srcIp.version == 6;
    std::vector<std::uint8_t> icmp(8 + quote, 0);
    if (!v6) {
        icmp[0] = 3;  // destination unreachable
        icmp[1] = 3;  // port unreachable
    } else {
        icmp[0] = 1;  // destination unreachable
        icmp[1] = 4;  // port unreachable
    }
    std::copy_n(original.begin(), quote, icmp.begin() + 8);

    const auto proto = static_cast<std::uint8_t>(v6 ? 58 : 1);
    std::vector<std::uint8_t> pkt =
        v6 ? ipv6Header(info.dstIp, info.srcIp, proto, static_cast<std::uint16_t>(icmp.size()))
           : ipv4Header(info.dstIp, info.srcIp, proto, static_cast<std::uint16_t>(20 + icmp.size()));
    const std::size_t l4 = pkt.size();
    pkt.insert(pkt.end(), icmp.begin(), icmp.end());
    checksumTransport(pkt, l4, proto, v6, 2, v6);
    return pkt;
}

}  // namespace aifw
