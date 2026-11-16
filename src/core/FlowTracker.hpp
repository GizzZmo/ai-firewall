// 5-tuple flyttabell med tidsavbrudd og statistikk per flyt.
#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "Types.hpp"

namespace aifw {

/// Welfords algoritme: numerisk stabil løpende middelverdi/varians i O(1) minne.
class RunningStats {
public:
    void add(double x) noexcept {
        ++n_;
        const double delta = x - mean_;
        mean_ += delta / static_cast<double>(n_);
        m2_ += delta * (x - mean_);
    }
    [[nodiscard]] std::uint64_t count() const noexcept { return n_; }
    [[nodiscard]] double mean() const noexcept { return n_ ? mean_ : 0.0; }
    [[nodiscard]] double variance() const noexcept { return n_ > 1 ? m2_ / static_cast<double>(n_ - 1) : 0.0; }
    [[nodiscard]] double stddev() const noexcept { return std::sqrt(variance()); }

private:
    std::uint64_t n_{0};
    double mean_{0.0};
    double m2_{0.0};
};

struct FlowStats {
    TimePoint firstSeen{};
    TimePoint lastSeen{};
    std::uint64_t fwdPackets{0};  // utgående (local -> remote)
    std::uint64_t bwdPackets{0};  // inngående (remote -> local)
    std::uint64_t fwdBytes{0};
    std::uint64_t bwdBytes{0};
    RunningStats pktLen;
    RunningStats iatMs;    // inter-arrival time
    RunningStats entropy;  // payload-entropi for samplede pakker
    std::uint32_t synCount{0}, finCount{0}, rstCount{0}, pshCount{0};
    bool finSeen{false};
    bool rstSeen{false};
    std::uint32_t processId{0};
    std::string appPath;  // UTF-8

    [[nodiscard]] std::uint64_t totalPackets() const noexcept { return fwdPackets + bwdPackets; }
};

struct FlowTrackerConfig {
    std::chrono::milliseconds tcpIdleTimeout{std::chrono::minutes(5)};
    std::chrono::milliseconds udpIdleTimeout{std::chrono::seconds(60)};
    std::chrono::milliseconds closedTimeout{std::chrono::seconds(10)};  // etter FIN/RST
    std::chrono::milliseconds otherIdleTimeout{std::chrono::seconds(30)};
    std::size_t maxFlows{200'000};
    std::uint32_t entropySamplePackets{8};  // antall første payload-pakker som entropi beregnes for
};

/// Trådsikker flyttabell. Delt i shards med egen mutex for å redusere lås-konkurranse
/// mellom flere WinDivert-arbeidertråder.
class FlowTracker {
public:
    static constexpr std::size_t kShards = 16;

    explicit FlowTracker(FlowTrackerConfig cfg = {});

    /// Oppdaterer (eller oppretter) flyten for pakken og returnerer en kopi av
    /// statistikken etter oppdatering. nullopt hvis tabellen er full.
    std::optional<FlowStats> update(const PacketInfo& pkt, TimePoint now);

    /// Henter kopi av flytstatistikk.
    [[nodiscard]] std::optional<FlowStats> get(const FlowKey& key) const;

    /// Fjerner utløpte flyter. Returnerer antall fjernet. Callback kalles for hver
    /// fjernet flyt (f.eks. for læringsmodus/eksport) – uten at shard-låsen holdes.
    std::size_t expire(TimePoint now,
                       const std::function<void(const FlowKey&, const FlowStats&)>& onExpired = {});

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::uint64_t droppedNewFlows() const noexcept { return dropped_.load(); }
    [[nodiscard]] const FlowTrackerConfig& config() const noexcept { return cfg_; }

    /// Tidsavbrudd som gjelder for gitt flyt nå.
    [[nodiscard]] std::chrono::milliseconds timeoutFor(const FlowKey& key, const FlowStats& s) const noexcept;

private:
    struct Shard {
        mutable std::mutex mutex;
        std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows;
    };
    Shard& shardFor(const FlowKey& key) const noexcept;

    FlowTrackerConfig cfg_;
    mutable std::array<Shard, kShards> shards_;
    std::atomic<std::size_t> total_{0};
    std::atomic<std::uint64_t> dropped_{0};
};

}  // namespace aifw
