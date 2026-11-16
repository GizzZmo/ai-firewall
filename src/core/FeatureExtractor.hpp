// Parsing av rå IP-pakker og beregning av flytbaserte features.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "FeatureSchema.hpp"
#include "Types.hpp"

namespace aifw {

struct FlowStats;  // fra FlowTracker.hpp

class FeatureExtractor {
public:
    /// Maks antall payload-bytes som brukes til entropi (begrenser CPU i pakkeveien).
    static constexpr std::size_t kEntropySampleBytes = 256;

    /// Portabel parser for IPv4/IPv6 + TCP/UDP/ICMP. Håndterer IPv6 extension headers
    /// (hop-by-hop, routing, destination options, fragment). Returnerer nullopt ved
    /// avkortede eller ugyldige pakker. Ingen allokering bortsett fra PacketInfo selv.
    [[nodiscard]] static std::optional<PacketInfo> parse(std::span<const std::uint8_t> packet,
                                                         Direction direction) noexcept;

#ifdef _WIN32
    /// Windows-variant som bruker WinDivertHelperParsePacket (samme resultat, men
    /// lener seg på WinDivert sin validering). Definert i FeatureExtractorWin.cpp.
    [[nodiscard]] static std::optional<PacketInfo> parseWinDivert(std::span<const std::uint8_t> packet,
                                                                  Direction direction) noexcept;
#endif

    /// Lager feature-vektor for en flyt. Rekkefølge iht. FeatureSchema.hpp.
    [[nodiscard]] static FeatureVector extract(const FlowKey& key, const FlowStats& stats) noexcept;
};

}  // namespace aifw
