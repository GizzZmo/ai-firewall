// Windows-spesifikk parsing via WinDivertHelperParsePacket.
#ifdef _WIN32
#include "FeatureExtractor.hpp"

#include <windivert.h>

namespace aifw {

std::optional<PacketInfo> FeatureExtractor::parseWinDivert(std::span<const std::uint8_t> packet,
                                                           Direction direction) noexcept {
    PWINDIVERT_IPHDR ip = nullptr;
    PWINDIVERT_IPV6HDR ip6 = nullptr;
    UINT8 proto = 0;
    PWINDIVERT_ICMPHDR icmp = nullptr;
    PWINDIVERT_ICMPV6HDR icmp6 = nullptr;
    PWINDIVERT_TCPHDR tcp = nullptr;
    PWINDIVERT_UDPHDR udp = nullptr;
    PVOID data = nullptr;
    UINT dataLen = 0;

    if (!WinDivertHelperParsePacket(packet.data(), static_cast<UINT>(packet.size()), &ip, &ip6, &proto, &icmp,
                                    &icmp6, &tcp, &udp, &data, &dataLen, nullptr, nullptr)) {
        return std::nullopt;
    }

    PacketInfo info;
    info.direction = direction;
    info.protocol = static_cast<Protocol>(proto);
    info.totalLength = static_cast<std::uint32_t>(packet.size());
    if (ip) {
        info.srcIp = IpAddress::fromBytes(reinterpret_cast<const std::uint8_t*>(&ip->SrcAddr), 4);
        info.dstIp = IpAddress::fromBytes(reinterpret_cast<const std::uint8_t*>(&ip->DstAddr), 4);
        info.ttl = ip->TTL;
    } else if (ip6) {
        info.srcIp = IpAddress::fromBytes(reinterpret_cast<const std::uint8_t*>(ip6->SrcAddr), 6);
        info.dstIp = IpAddress::fromBytes(reinterpret_cast<const std::uint8_t*>(ip6->DstAddr), 6);
        info.ttl = ip6->HopLimit;
    } else {
        return std::nullopt;
    }
    if (tcp) {
        info.srcPort = WinDivertHelperNtohs(tcp->SrcPort);
        info.dstPort = WinDivertHelperNtohs(tcp->DstPort);
        // WinDivert eksponerer flaggene som bitfelt; vi pakker dem tilbake i TCP-rekkefølge.
        info.tcpFlags = static_cast<std::uint8_t>((tcp->Fin ? tcpflags::FIN : 0) | (tcp->Syn ? tcpflags::SYN : 0) |
                                                  (tcp->Rst ? tcpflags::RST : 0) | (tcp->Psh ? tcpflags::PSH : 0) |
                                                  (tcp->Ack ? tcpflags::ACK : 0) | (tcp->Urg ? tcpflags::URG : 0));
    } else if (udp) {
        info.srcPort = WinDivertHelperNtohs(udp->SrcPort);
        info.dstPort = WinDivertHelperNtohs(udp->DstPort);
    } else if (icmp) {
        info.srcPort = icmp->Type;
        info.dstPort = icmp->Code;
    } else if (icmp6) {
        info.srcPort = icmp6->Type;
        info.dstPort = icmp6->Code;
    }
    info.payload = static_cast<const std::uint8_t*>(data);
    info.payloadLength = dataLen;
    return info;
}

}  // namespace aifw
#endif  // _WIN32
