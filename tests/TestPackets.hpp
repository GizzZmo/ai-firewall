// Hjelpere for å bygge rå IPv4/IPv6 + TCP/UDP-pakker i tester (ingen nettverk nødvendig).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Types.hpp"

namespace aifw::test {

inline void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v >> 8);
    b[off + 1] = static_cast<std::uint8_t>(v);
}

inline std::vector<std::uint8_t> l4(Protocol proto, std::uint16_t sp, std::uint16_t dp, std::uint8_t flags,
                                    const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> h;
    if (proto == Protocol::TCP) {
        h.assign(20, 0);
        put16(h, 0, sp);
        put16(h, 2, dp);
        h[12] = 5 << 4;
        h[13] = flags;
        put16(h, 14, 65535);
    } else if (proto == Protocol::UDP) {
        h.assign(8, 0);
        put16(h, 0, sp);
        put16(h, 2, dp);
        put16(h, 4, static_cast<std::uint16_t>(8 + payload.size()));
    } else {
        h.assign(4, 0);
        h[0] = static_cast<std::uint8_t>(sp);
        h[1] = static_cast<std::uint8_t>(dp);
    }
    h.insert(h.end(), payload.begin(), payload.end());
    return h;
}

inline std::vector<std::uint8_t> ipv4(const std::string& src, const std::string& dst, Protocol proto, std::uint16_t sp,
                                      std::uint16_t dp, std::uint8_t flags = 0,
                                      const std::vector<std::uint8_t>& payload = {}) {
    auto body = l4(proto, sp, dp, flags, payload);
    std::vector<std::uint8_t> p(20, 0);
    p[0] = 0x45;
    put16(p, 2, static_cast<std::uint16_t>(20 + body.size()));
    p[8] = 64;
    p[9] = static_cast<std::uint8_t>(proto);
    auto s = IpAddress::parse(src).value();
    auto d = IpAddress::parse(dst).value();
    std::copy_n(s.bytes.begin(), 4, p.begin() + 12);
    std::copy_n(d.bytes.begin(), 4, p.begin() + 16);
    p.insert(p.end(), body.begin(), body.end());
    return p;
}

inline std::vector<std::uint8_t> ipv6(const std::string& src, const std::string& dst, Protocol proto, std::uint16_t sp,
                                      std::uint16_t dp, std::uint8_t flags = 0,
                                      const std::vector<std::uint8_t>& payload = {}, bool withHopByHop = false) {
    auto body = l4(proto, sp, dp, flags, payload);
    std::vector<std::uint8_t> ext;
    if (withHopByHop) {
        ext.assign(8, 0);
        ext[0] = static_cast<std::uint8_t>(proto);  // next header
        ext[1] = 0;                                  // (0+1)*8 = 8 byte
    }
    std::vector<std::uint8_t> p(40, 0);
    p[0] = 0x60;
    put16(p, 4, static_cast<std::uint16_t>(ext.size() + body.size()));
    p[6] = withHopByHop ? 0 : static_cast<std::uint8_t>(proto);
    p[7] = 64;
    auto s = IpAddress::parse(src).value();
    auto d = IpAddress::parse(dst).value();
    std::copy(s.bytes.begin(), s.bytes.end(), p.begin() + 8);
    std::copy(d.bytes.begin(), d.bytes.end(), p.begin() + 24);
    p.insert(p.end(), ext.begin(), ext.end());
    p.insert(p.end(), body.begin(), body.end());
    return p;
}

}  // namespace aifw::test
