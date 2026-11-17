#include "HostTracker.hpp"

#include <algorithm>

namespace aifw {

// Hash for IpAddress (trengs for unordered_map).
struct IpAddressHash {
    std::size_t operator()(const IpAddress& ip) const noexcept {
        std::size_t h = ip.version;
        for (std::size_t i = 0; i < ip.length(); ++i) {
            h = h * 31 + ip.bytes[i];
        }
        return h;
    }
};

HostTracker::HostTracker(HostTrackerConfig cfg) : cfg_(std::move(cfg)) {}

bool HostTracker::onNewFlow(const FlowKey& key, TimePoint now, bool isSyn) {
    if (!cfg_.enabled) return false;

    std::lock_guard lock(mutex_);
    auto& stats = hosts_[key.remoteIp];  // default-construct hvis ny
    stats.lastSeen = now;

    // Legg til port hvis ny i vinduet.
    const auto cutoff = now - cfg_.window;
    bool portSeen = false;
    for (const auto& pe : stats.ports) {
        if (pe.port == key.remotePort && pe.time >= cutoff) {
            portSeen = true;
            break;
        }
    }
    if (!portSeen) {
        stats.ports.push_back({key.remotePort, now});
    }

    stats.flows.push_back(now);
    if (isSyn) stats.syns.push_back(now);

    // Tell bare innenfor vinduet.
    auto inWindow = [&](const auto& ts) { return ts >= cutoff; };
    const auto uniquePorts = std::count_if(stats.ports.begin(), stats.ports.end(),
                                           [&](const PortEvent& pe) { return pe.time >= cutoff; });
    const auto newFlows = std::count_if(stats.flows.begin(), stats.flows.end(), inWindow);
    const auto syns = std::count_if(stats.syns.begin(), stats.syns.end(), inWindow);

    const bool suspicious = uniquePorts > cfg_.maxUniquePorts || newFlows > cfg_.maxNewFlows ||
                            syns > cfg_.maxSyns;
    return suspicious;
}

void HostTracker::expire(TimePoint now) {
    std::lock_guard lock(mutex_);
    const auto cutoff = now - cfg_.window * 2;  // behold litt lenger for historikk
    for (auto it = hosts_.begin(); it != hosts_.end();) {
        auto& s = it->second;
        s.ports.erase(std::remove_if(s.ports.begin(), s.ports.end(),
                                     [&](const PortEvent& pe) { return pe.time < cutoff; }),
                      s.ports.end());
        s.flows.erase(std::remove_if(s.flows.begin(), s.flows.end(),
                                     [&](TimePoint t) { return t < cutoff; }),
                      s.flows.end());
        s.syns.erase(std::remove_if(s.syns.begin(), s.syns.end(),
                                    [&](TimePoint t) { return t < cutoff; }),
                     s.syns.end());
        if (s.ports.empty() && s.flows.empty() && s.lastSeen < cutoff) {
            it = hosts_.erase(it);
        } else {
            ++it;
        }
    }
}

std::size_t HostTracker::size() const {
    std::lock_guard lock(mutex_);
    return hosts_.size();
}

}  // namespace aifw
