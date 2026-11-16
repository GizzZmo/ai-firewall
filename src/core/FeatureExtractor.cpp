#include "FeatureExtractor.hpp"

#include <algorithm>
#include <cmath>

#include "FlowTracker.hpp"

namespace aifw {
namespace {

inline std::uint16_t be16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

// IPv6 extension headers vi kan hoppe over.
constexpr std::uint8_t kHopByHop = 0, kRouting = 43, kFragment = 44, kDestOpts = 60, kNoNext = 59;

}  // namespace

std::optional<PacketInfo> FeatureExtractor::parse(std::span<const std::uint8_t> pkt, Direction direction) noexcept {
    if (pkt.empty()) return std::nullopt;
    PacketInfo info;
    info.direction = direction;
    const std::uint8_t* d = pkt.data();
    const std::size_t n = pkt.size();
    const std::uint8_t version = d[0] >> 4;

    std::size_t l4Offset = 0;
    std::uint8_t nextProto = 0;
    std::size_t ipEnd = n;  // slutt på IP-pakken iht. header (kan være < bufferlengde)

    if (version == 4) {
        if (n < 20) return std::nullopt;
        const std::size_t ihl = static_cast<std::size_t>(d[0] & 0x0F) * 4;
        if (ihl < 20 || ihl > n) return std::nullopt;
        const std::size_t total = be16(d + 2);
        if (total < ihl || total > n) return std::nullopt;
        ipEnd = total;
        info.totalLength = static_cast<std::uint32_t>(total);
        info.ttl = d[8];
        nextProto = d[9];
        info.srcIp = IpAddress::fromBytes(d + 12, 4);
        info.dstIp = IpAddress::fromBytes(d + 16, 4);
        // Fragmenter med offset != 0 har ikke L4-header.
        const std::uint16_t fragOff = be16(d + 6) & 0x1FFF;
        l4Offset = ihl;
        if (fragOff != 0) {
            info.protocol = static_cast<Protocol>(nextProto);
            info.payload = d + ihl;
            info.payloadLength = total - ihl;
            return info;
        }
    } else if (version == 6) {
        if (n < 40) return std::nullopt;
        const std::size_t payloadLen = be16(d + 4);
        if (40 + payloadLen > n) return std::nullopt;
        ipEnd = 40 + payloadLen;
        info.totalLength = static_cast<std::uint32_t>(ipEnd);
        info.ttl = d[7];
        info.srcIp = IpAddress::fromBytes(d + 8, 6);
        info.dstIp = IpAddress::fromBytes(d + 24, 6);
        nextProto = d[6];
        l4Offset = 40;
        // Gå gjennom extension headers (maks 8 for å unngå løkker på ondsinnede pakker).
        for (int guard = 0; guard < 8; ++guard) {
            if (nextProto == kHopByHop || nextProto == kRouting || nextProto == kDestOpts) {
                if (l4Offset + 2 > ipEnd) return std::nullopt;
                const std::size_t len = (static_cast<std::size_t>(d[l4Offset + 1]) + 1) * 8;
                nextProto = d[l4Offset];
                l4Offset += len;
            } else if (nextProto == kFragment) {
                if (l4Offset + 8 > ipEnd) return std::nullopt;
                const std::uint16_t off = be16(d + l4Offset + 2) >> 3;
                nextProto = d[l4Offset];
                l4Offset += 8;
                if (off != 0) {  // ikke første fragment: ingen L4-header
                    info.protocol = static_cast<Protocol>(nextProto);
                    info.payload = d + l4Offset;
                    info.payloadLength = ipEnd - l4Offset;
                    return info;
                }
            } else {
                break;
            }
            if (l4Offset > ipEnd) return std::nullopt;
        }
        if (nextProto == kNoNext) {
            info.protocol = Protocol::Any;
            return info;
        }
    } else {
        return std::nullopt;
    }

    info.protocol = static_cast<Protocol>(nextProto);
    std::size_t payloadOffset = l4Offset;
    switch (nextProto) {
        case 6: {  // TCP
            if (l4Offset + 20 > ipEnd) return std::nullopt;
            const std::uint8_t* t = d + l4Offset;
            info.srcPort = be16(t);
            info.dstPort = be16(t + 2);
            const std::size_t dataOff = static_cast<std::size_t>(t[12] >> 4) * 4;
            if (dataOff < 20 || l4Offset + dataOff > ipEnd) return std::nullopt;
            info.tcpFlags = t[13];
            payloadOffset = l4Offset + dataOff;
            break;
        }
        case 17: {  // UDP
            if (l4Offset + 8 > ipEnd) return std::nullopt;
            const std::uint8_t* u = d + l4Offset;
            info.srcPort = be16(u);
            info.dstPort = be16(u + 2);
            payloadOffset = l4Offset + 8;
            break;
        }
        case 1:
        case 58: {  // ICMP / ICMPv6: type/kode i "port"-feltene for regelmatching
            if (l4Offset + 4 > ipEnd) return std::nullopt;
            info.srcPort = d[l4Offset];      // type
            info.dstPort = d[l4Offset + 1];  // kode
            payloadOffset = l4Offset + 4;
            break;
        }
        default:
            break;
    }
    if (payloadOffset <= ipEnd) {
        info.payload = d + payloadOffset;
        info.payloadLength = ipEnd - payloadOffset;
    }
    return info;
}

FeatureVector FeatureExtractor::extract(const FlowKey& key, const FlowStats& s) noexcept {
    FeatureVector f{};
    auto set = [&f](Feature idx, double v) {
        // Beskytt modellen mot NaN/Inf (f.eks. ved deling på null).
        f[static_cast<std::size_t>(idx)] = std::isfinite(v) ? static_cast<float>(v) : 0.0f;
    };
    const double duration =
        std::chrono::duration<double>(s.lastSeen - s.firstSeen).count();
    const double packets = static_cast<double>(s.fwdPackets + s.bwdPackets);
    const double bytes = static_cast<double>(s.fwdBytes + s.bwdBytes);
    const double effDuration = std::max(duration, 1e-3);  // unngå ekstreme rater for 1-pakke-flyter

    set(Feature::DurationSec, duration);
    set(Feature::FwdPackets, static_cast<double>(s.fwdPackets));
    set(Feature::BwdPackets, static_cast<double>(s.bwdPackets));
    set(Feature::FwdBytes, static_cast<double>(s.fwdBytes));
    set(Feature::BwdBytes, static_cast<double>(s.bwdBytes));
    set(Feature::PktLenMean, s.pktLen.mean());
    set(Feature::PktLenStd, s.pktLen.stddev());
    set(Feature::IatMeanMs, s.iatMs.mean());
    set(Feature::IatStdMs, s.iatMs.stddev());
    set(Feature::SynCount, s.synCount);
    set(Feature::FinCount, s.finCount);
    set(Feature::RstCount, s.rstCount);
    set(Feature::PshCount, s.pshCount);
    set(Feature::PayloadEntropyMean, s.entropy.mean());
    set(Feature::DstPortNorm, static_cast<double>(key.remotePort) / 65535.0);
    set(Feature::ProtocolTcp, key.protocol == Protocol::TCP ? 1.0 : 0.0);
    set(Feature::ProtocolUdp, key.protocol == Protocol::UDP ? 1.0 : 0.0);
    set(Feature::PacketsPerSec, packets / effDuration);
    set(Feature::BytesPerSec, bytes / effDuration);
    set(Feature::FwdBwdRatio, static_cast<double>(s.fwdPackets) / static_cast<double>(s.bwdPackets + 1));
    return f;
}

}  // namespace aifw
