#include "FlowTracker.hpp"

#include <algorithm>
#include <span>

#include "Entropy.hpp"
#include "FeatureExtractor.hpp"

namespace aifw {

FlowTracker::FlowTracker(FlowTrackerConfig cfg) : cfg_(cfg) {}

FlowTracker::Shard& FlowTracker::shardFor(const FlowKey& key) const noexcept {
    return shards_[FlowKeyHash{}(key) % kShards];
}

std::chrono::milliseconds FlowTracker::timeoutFor(const FlowKey& key, const FlowStats& s) const noexcept {
    if (s.rstSeen || s.finSeen) return cfg_.closedTimeout;
    switch (key.protocol) {
        case Protocol::TCP: return cfg_.tcpIdleTimeout;
        case Protocol::UDP: return cfg_.udpIdleTimeout;
        default: return cfg_.otherIdleTimeout;
    }
}

std::optional<FlowStats> FlowTracker::update(const PacketInfo& pkt, TimePoint now) {
    const FlowKey key = pkt.flowKey();
    Shard& shard = shardFor(key);
    std::lock_guard lock(shard.mutex);

    auto it = shard.flows.find(key);
    if (it == shard.flows.end()) {
        if (total_.load(std::memory_order_relaxed) >= cfg_.maxFlows) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;
        }
        FlowStats fresh;
        fresh.firstSeen = now;
        fresh.lastSeen = now;
        fresh.processId = pkt.processId;
        fresh.appPath = pkt.appPath;
        it = shard.flows.emplace(key, std::move(fresh)).first;
        total_.fetch_add(1, std::memory_order_relaxed);
    } else {
        const double iat = std::chrono::duration<double, std::milli>(now - it->second.lastSeen).count();
        it->second.iatMs.add(iat < 0 ? 0 : iat);
        it->second.lastSeen = now;
    }

    FlowStats& s = it->second;
    if (s.appPath.empty() && !pkt.appPath.empty()) {
        s.appPath = pkt.appPath;
        s.processId = pkt.processId;
    }
    if (pkt.direction == Direction::Inbound) {
        ++s.bwdPackets;
        s.bwdBytes += pkt.totalLength;
    } else {
        ++s.fwdPackets;
        s.fwdBytes += pkt.totalLength;
    }
    s.pktLen.add(static_cast<double>(pkt.totalLength));

    if (pkt.protocol == Protocol::TCP) {
        if (pkt.tcpFlags & tcpflags::SYN) ++s.synCount;
        if (pkt.tcpFlags & tcpflags::FIN) { ++s.finCount; s.finSeen = true; }
        if (pkt.tcpFlags & tcpflags::RST) { ++s.rstCount; s.rstSeen = true; }
        if (pkt.tcpFlags & tcpflags::PSH) ++s.pshCount;
    }

    // Entropi kun for de første N payload-pakkene: gir signal tidlig uten å
    // koste CPU for lange, store flyter.
    if (pkt.payload && pkt.payloadLength > 0 && s.entropy.count() < cfg_.entropySamplePackets) {
        const std::size_t len = std::min(pkt.payloadLength, FeatureExtractor::kEntropySampleBytes);
        s.entropy.add(shannonEntropy(std::span(pkt.payload, len)));
    }
    return s;
}

std::optional<FlowStats> FlowTracker::get(const FlowKey& key) const {
    Shard& shard = shardFor(key);
    std::lock_guard lock(shard.mutex);
    auto it = shard.flows.find(key);
    if (it == shard.flows.end()) return std::nullopt;
    return it->second;
}

std::size_t FlowTracker::expire(TimePoint now, const std::function<void(const FlowKey&, const FlowStats&)>& onExpired) {
    std::size_t removed = 0;
    std::vector<std::pair<FlowKey, FlowStats>> expired;
    for (auto& shard : shards_) {
        {
            std::lock_guard lock(shard.mutex);
            for (auto it = shard.flows.begin(); it != shard.flows.end();) {
                if (now - it->second.lastSeen >= timeoutFor(it->first, it->second)) {
                    if (onExpired) expired.emplace_back(it->first, std::move(it->second));
                    it = shard.flows.erase(it);
                    ++removed;
                } else {
                    ++it;
                }
            }
        }
        // Callback utenfor låsen, slik at mottaker ikke kan forårsake deadlock.
        for (const auto& [k, s] : expired) onExpired(k, s);
        expired.clear();
    }
    total_.fetch_sub(removed, std::memory_order_relaxed);
    return removed;
}

std::size_t FlowTracker::size() const { return total_.load(std::memory_order_relaxed); }

}  // namespace aifw
