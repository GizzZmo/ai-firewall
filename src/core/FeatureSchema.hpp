// Feature-skjema delt mellom C++ og Python (ml/feature_schema.json).
// REKKEFØLGEN HER MÅ VÆRE IDENTISK MED ml/feature_schema.json.
// Testen FeatureSchemaTest verifiserer dette automatisk.
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace aifw {

inline constexpr std::size_t kFeatureSchemaVersion = 1;

enum class Feature : std::size_t {
    DurationSec = 0,
    FwdPackets,
    BwdPackets,
    FwdBytes,
    BwdBytes,
    PktLenMean,
    PktLenStd,
    IatMeanMs,
    IatStdMs,
    SynCount,
    FinCount,
    RstCount,
    PshCount,
    PayloadEntropyMean,
    DstPortNorm,
    ProtocolTcp,
    ProtocolUdp,
    PacketsPerSec,
    BytesPerSec,
    FwdBwdRatio,
    Count  // må stå sist
};

inline constexpr std::size_t kFeatureCount = static_cast<std::size_t>(Feature::Count);

inline constexpr std::array<std::string_view, kFeatureCount> kFeatureNames = {
    "duration_sec",   "fwd_packets", "bwd_packets",          "fwd_bytes",      "bwd_bytes",
    "pkt_len_mean",   "pkt_len_std", "iat_mean_ms",          "iat_std_ms",     "syn_count",
    "fin_count",      "rst_count",   "psh_count",            "payload_entropy_mean", "dst_port_norm",
    "protocol_tcp",   "protocol_udp", "packets_per_sec",     "bytes_per_sec",  "fwd_bwd_ratio",
};

using FeatureVector = std::array<float, kFeatureCount>;

}  // namespace aifw
