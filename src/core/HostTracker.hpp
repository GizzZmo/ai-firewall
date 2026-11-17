// Vertsnivå-sporing: oppdager angrep som involverer mange flyter fra samme remote-IP
// (portskanning, brute-force, etc.). AI ser bare én flyt om gangen; dette fyller gapet.
#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "Types.hpp"

namespace aifw {

struct HostTrackerConfig {
    /// Tidsvindu for telling av unike porter og nye flyter.
    std::chrono::seconds window{std::chrono::seconds(10)};
    /// Maks unike remote-porter fra samme remote-IP i vinduet før alarm.
    std::uint32_t maxUniquePorts{50};
    /// Maks nye flyter fra samme remote-IP i vinduet før alarm.
    std::uint32_t maxNewFlows{100};
    /// Maks SYN-pakker (uten full handshake) i vinduet.
    std::uint32_t maxSyns{200};
    bool enabled{true};
};

/// Enkel detektor. Kalles på første pakke i en ny flyt.
/// Returnerer true hvis terskel er overskredet (bør blokkeres / varsles).
class HostTracker {
public:
    explicit HostTracker(HostTrackerConfig cfg = {});

    /// Registrer en ny flyt. Returnerer true hvis hosten nå er mistenkelig.
    /// `isSyn` indikerer om første pakke var TCP SYN (uten ACK).
    [[nodiscard]] bool onNewFlow(const FlowKey& key, TimePoint now, bool isSyn) ;

    /// Periodisk opprydding av gamle oppføringer.
    void expire(TimePoint now);

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] const HostTrackerConfig& config() const noexcept { return cfg_; }

private:
    struct PortEvent {
        std::uint16_t port;
        TimePoint time;
    };
    struct HostStats {
        std::vector<PortEvent> ports;     // unike porter med tidsstempel
        std::vector<TimePoint> flows;     // tidsstempler for nye flyter
        std::vector<TimePoint> syns;
        TimePoint lastSeen{};
    };

    HostTrackerConfig cfg_;
    mutable std::mutex mutex_;
    std::unordered_map<IpAddress, HostStats, std::hash<IpAddress>> hosts_;
};

}  // namespace aifw
