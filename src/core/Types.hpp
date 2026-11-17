// Felles grunntyper for AI-Firewall: IP-adresser, 5-tuple flytnøkler, verdikter.
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace aifw {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

enum class Verdict : std::uint8_t { Allow, Block, Unknown };
enum class Direction : std::uint8_t { Inbound, Outbound, Any };
enum class Protocol : std::uint8_t { Any = 0, ICMP = 1, TCP = 6, UDP = 17, ICMPv6 = 58 };

std::string_view toString(Verdict v) noexcept;
std::string_view toString(Direction d) noexcept;
std::string_view toString(Protocol p) noexcept;

/// IPv4 eller IPv6-adresse lagret i nettverks-byte-rekkefølge (16 byte, IPv4 i de 4 første).
struct IpAddress {
    std::array<std::uint8_t, 16> bytes{};
    std::uint8_t version{0};  // 4, 6 eller 0 (ugyldig)

    static IpAddress v4(std::uint32_t hostOrder) noexcept;
    static IpAddress fromBytes(const std::uint8_t* data, std::uint8_t version) noexcept;
    /// Parser "192.168.1.1" eller "2001:db8::1". Returnerer nullopt ved feil.
    static std::optional<IpAddress> parse(std::string_view text);

    [[nodiscard]] std::size_t length() const noexcept { return version == 6 ? 16 : (version == 4 ? 4 : 0); }
    [[nodiscard]] bool isValid() const noexcept { return version == 4 || version == 6; }
    [[nodiscard]] std::string toString() const;

    friend bool operator==(const IpAddress&, const IpAddress&) = default;
    friend auto operator<=>(const IpAddress&, const IpAddress&) = default;
};

/// CIDR-blokk, f.eks. 10.0.0.0/8 eller fe80::/10.
struct Cidr {
    IpAddress network;
    std::uint8_t prefix{0};

    static std::optional<Cidr> parse(std::string_view text);  // "a.b.c.d/n" eller bare adresse
    [[nodiscard]] bool contains(const IpAddress& ip) const noexcept;
};

/// Kanonisk 5-tuple. "local" er alltid maskinens side, "remote" er motparten,
/// slik at begge retninger i samme forbindelse havner i samme flyt.
struct FlowKey {
    IpAddress localIp;
    IpAddress remoteIp;
    std::uint16_t localPort{0};
    std::uint16_t remotePort{0};
    Protocol protocol{Protocol::Any};

    friend bool operator==(const FlowKey&, const FlowKey&) = default;
    [[nodiscard]] std::string toString() const;
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const noexcept;
};

/// TCP-flagg (samme bitposisjoner som i TCP-headeren).
namespace tcpflags {
inline constexpr std::uint8_t FIN = 0x01;
inline constexpr std::uint8_t SYN = 0x02;
inline constexpr std::uint8_t RST = 0x04;
inline constexpr std::uint8_t PSH = 0x08;
inline constexpr std::uint8_t ACK = 0x10;
inline constexpr std::uint8_t URG = 0x20;
}  // namespace tcpflags

/// Resultat av parsing av én pakke. Payload-pekeren peker inn i original-bufferen
/// og er kun gyldig så lenge bufferen lever (ikke-eiende view).
struct PacketInfo {
    IpAddress srcIp;
    IpAddress dstIp;
    std::uint16_t srcPort{0};
    std::uint16_t dstPort{0};
    Protocol protocol{Protocol::Any};
    std::uint8_t tcpFlags{0};
    std::uint32_t tcpSeq{0};
    std::uint32_t tcpAck{0};
    std::uint8_t ttl{0};
    std::uint32_t totalLength{0};  // hele IP-pakken
    const std::uint8_t* payload{nullptr};
    std::size_t payloadLength{0};
    Direction direction{Direction::Outbound};
    std::uint32_t processId{0};    // 0 = ukjent
    std::string appPath;           // UTF-8, tom = ukjent (fylles fra WinDivert FLOW-laget)

    /// Bygger kanonisk flytnøkkel ut fra retningen.
    [[nodiscard]] FlowKey flowKey() const noexcept;
};

}  // namespace aifw
