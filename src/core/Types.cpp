#include "Types.hpp"

#include <charconv>
#include <cstdio>
#include <cstring>
#include <vector>

namespace aifw {

std::string_view toString(Verdict v) noexcept {
    switch (v) {
        case Verdict::Allow: return "allow";
        case Verdict::Block: return "block";
        default: return "unknown";
    }
}

std::string_view toString(Direction d) noexcept {
    switch (d) {
        case Direction::Inbound: return "in";
        case Direction::Outbound: return "out";
        default: return "any";
    }
}

std::string_view toString(Protocol p) noexcept {
    switch (p) {
        case Protocol::TCP: return "tcp";
        case Protocol::UDP: return "udp";
        case Protocol::ICMP: return "icmp";
        case Protocol::ICMPv6: return "icmpv6";
        default: return "any";
    }
}

IpAddress IpAddress::v4(std::uint32_t h) noexcept {
    IpAddress a;
    a.version = 4;
    a.bytes[0] = static_cast<std::uint8_t>(h >> 24);
    a.bytes[1] = static_cast<std::uint8_t>(h >> 16);
    a.bytes[2] = static_cast<std::uint8_t>(h >> 8);
    a.bytes[3] = static_cast<std::uint8_t>(h);
    return a;
}

IpAddress IpAddress::fromBytes(const std::uint8_t* data, std::uint8_t ver) noexcept {
    IpAddress a;
    a.version = ver;
    std::memcpy(a.bytes.data(), data, ver == 6 ? 16 : 4);
    return a;
}

namespace {

std::optional<IpAddress> parseV4(std::string_view s) {
    IpAddress a;
    a.version = 4;
    std::size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        if (pos >= s.size()) return std::nullopt;
        unsigned value = 0;
        auto [ptr, ec] = std::from_chars(s.data() + pos, s.data() + s.size(), value);
        if (ec != std::errc{} || value > 255) return std::nullopt;
        const auto consumed = static_cast<std::size_t>(ptr - (s.data() + pos));
        if (consumed == 0 || consumed > 3) return std::nullopt;
        a.bytes[i] = static_cast<std::uint8_t>(value);
        pos += consumed;
        if (i < 3) {
            if (pos >= s.size() || s[pos] != '.') return std::nullopt;
            ++pos;
        }
    }
    if (pos != s.size()) return std::nullopt;
    return a;
}

std::optional<IpAddress> parseV6(std::string_view s) {
    // Støtter full form, "::"-komprimering og innebygd IPv4 i siste del (::ffff:1.2.3.4).
    std::vector<std::uint16_t> head, tail;
    bool seenGap = false;
    std::size_t i = 0;
    if (s.starts_with("::")) {
        seenGap = true;
        i = 2;
    }
    std::optional<IpAddress> embeddedV4;
    while (i < s.size()) {
        std::size_t end = s.find(':', i);
        std::string_view part = s.substr(i, end == std::string_view::npos ? s.size() - i : end - i);
        if (part.empty()) return std::nullopt;
        if (part.find('.') != std::string_view::npos) {
            if (end != std::string_view::npos) return std::nullopt;
            embeddedV4 = parseV4(part);
            if (!embeddedV4) return std::nullopt;
            i = s.size();
            break;
        }
        if (part.size() > 4) return std::nullopt;
        unsigned v = 0;
        auto [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), v, 16);
        if (ec != std::errc{} || ptr != part.data() + part.size()) return std::nullopt;
        (seenGap ? tail : head).push_back(static_cast<std::uint16_t>(v));
        if (end == std::string_view::npos) {
            i = s.size();
        } else if (end + 1 < s.size() && s[end + 1] == ':') {
            if (seenGap) return std::nullopt;
            seenGap = true;
            i = end + 2;
        } else {
            if (end + 1 >= s.size()) return std::nullopt;  // avsluttende enkelt ':'
            i = end + 1;
        }
    }
    const std::size_t groups = head.size() + tail.size() + (embeddedV4 ? 2 : 0);
    if (groups > 8 || (!seenGap && groups != 8)) return std::nullopt;
    if (seenGap && groups == 8) return std::nullopt;
    std::vector<std::uint16_t> all(head);
    all.resize(8 - tail.size() - (embeddedV4 ? 2 : 0), 0);
    all.insert(all.end(), tail.begin(), tail.end());
    IpAddress a;
    a.version = 6;
    for (std::size_t g = 0; g < all.size(); ++g) {
        a.bytes[g * 2] = static_cast<std::uint8_t>(all[g] >> 8);
        a.bytes[g * 2 + 1] = static_cast<std::uint8_t>(all[g]);
    }
    if (embeddedV4) std::memcpy(a.bytes.data() + 12, embeddedV4->bytes.data(), 4);
    return a;
}

}  // namespace

std::optional<IpAddress> IpAddress::parse(std::string_view text) {
    if (text.find(':') != std::string_view::npos) return parseV6(text);
    return parseV4(text);
}

std::string IpAddress::toString() const {
    char buf[64];
    if (version == 4) {
        std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
        return buf;
    }
    if (version == 6) {
        // Enkel (ikke-komprimert) men gyldig form.
        std::string out;
        for (int g = 0; g < 8; ++g) {
            std::snprintf(buf, sizeof buf, "%x", (bytes[g * 2] << 8) | bytes[g * 2 + 1]);
            if (g) out += ':';
            out += buf;
        }
        return out;
    }
    return "<invalid>";
}

std::optional<Cidr> Cidr::parse(std::string_view text) {
    const auto slash = text.find('/');
    auto ip = IpAddress::parse(text.substr(0, slash));
    if (!ip) return std::nullopt;
    const unsigned maxPrefix = ip->version == 6 ? 128u : 32u;
    unsigned prefix = maxPrefix;
    if (slash != std::string_view::npos) {
        auto rest = text.substr(slash + 1);
        auto [ptr, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), prefix);
        if (ec != std::errc{} || ptr != rest.data() + rest.size() || prefix > maxPrefix) return std::nullopt;
    }
    Cidr c;
    c.network = *ip;
    c.prefix = static_cast<std::uint8_t>(prefix);
    // Nullstill host-bits slik at nettverksadressen er normalisert.
    for (unsigned bit = prefix; bit < maxPrefix; ++bit) c.network.bytes[bit / 8] &= static_cast<std::uint8_t>(~(0x80u >> (bit % 8)));
    return c;
}

bool Cidr::contains(const IpAddress& ip) const noexcept {
    if (ip.version != network.version) return false;
    const unsigned fullBytes = prefix / 8;
    if (std::memcmp(ip.bytes.data(), network.bytes.data(), fullBytes) != 0) return false;
    const unsigned rem = prefix % 8;
    if (rem == 0) return true;
    const auto mask = static_cast<std::uint8_t>(0xFFu << (8 - rem));
    return (ip.bytes[fullBytes] & mask) == (network.bytes[fullBytes] & mask);
}

std::string FlowKey::toString() const {
    return std::string(aifw::toString(protocol)) + " " + localIp.toString() + ":" + std::to_string(localPort) +
           " <-> " + remoteIp.toString() + ":" + std::to_string(remotePort);
}

std::size_t FlowKeyHash::operator()(const FlowKey& k) const noexcept {
    // FNV-1a over feltene: rask og god nok spredning for flyttabellen.
    std::uint64_t h = 1469598103934665603ull;
    auto mix = [&h](const void* p, std::size_t n) {
        const auto* b = static_cast<const std::uint8_t*>(p);
        for (std::size_t i = 0; i < n; ++i) {
            h ^= b[i];
            h *= 1099511628211ull;
        }
    };
    mix(k.localIp.bytes.data(), 16);
    mix(&k.localIp.version, 1);
    mix(k.remoteIp.bytes.data(), 16);
    mix(&k.localPort, 2);
    mix(&k.remotePort, 2);
    mix(&k.protocol, 1);
    return static_cast<std::size_t>(h);
}

FlowKey PacketInfo::flowKey() const noexcept {
    FlowKey k;
    k.protocol = protocol;
    if (direction == Direction::Inbound) {
        k.localIp = dstIp;
        k.localPort = dstPort;
        k.remoteIp = srcIp;
        k.remotePort = srcPort;
    } else {
        k.localIp = srcIp;
        k.localPort = srcPort;
        k.remoteIp = dstIp;
        k.remotePort = dstPort;
    }
    return k;
}

}  // namespace aifw
