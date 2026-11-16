// Læringsmodus: observer trafikk uten å blokkere, og foreslå regler basert på det
// som faktisk brukes. Typisk kjøres dette noen dager før håndhevelse slås på.
#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <nlohmann/json_fwd.hpp>

#include "RuleEngine.hpp"
#include "Types.hpp"

namespace aifw {

struct ObservationKey {
    std::string app;  // UTF-8, kan være tom
    Direction direction{Direction::Outbound};
    Protocol protocol{Protocol::Any};
    std::uint16_t remotePort{0};
    auto operator<=>(const ObservationKey&) const = default;
};

struct Observation {
    std::uint64_t flows{0};
    std::uint64_t aiFlagged{0};       // antall flyter AI ville blokkert
    float maxScore{0.0f};
    std::set<std::string> remoteIps;  // begrenset til kMaxIpsPerObservation
};

class LearningMode {
public:
    static constexpr std::size_t kMaxIpsPerObservation = 32;
    static constexpr std::size_t kMaxObservations = 50'000;

    explicit LearningMode(bool enabled = false) : enabled_(enabled) {}

    void setEnabled(bool on) noexcept { enabled_.store(on); }
    [[nodiscard]] bool enabled() const noexcept { return enabled_.load(); }

    /// Registrer en ny flyt (kalles én gang per flyt).
    void recordFlow(const MatchContext& ctx);
    /// Registrer at AI ville blokkert flyten.
    void recordAiVerdict(const MatchContext& ctx, float score);

    /// Foreslår allow-regler for kombinasjoner sett minst minFlows ganger uten AI-flagg,
    /// og deny-regler for kombinasjoner som AI har flagget gjentatte ganger.
    [[nodiscard]] std::vector<Rule> suggestRules(std::uint64_t minFlows = 3, std::uint64_t minAiFlags = 3) const;

    [[nodiscard]] std::map<ObservationKey, Observation> snapshot() const;
    [[nodiscard]] nlohmann::json toJson() const;
    void loadJson(const nlohmann::json& j);
    void save(const std::filesystem::path& path) const;
    void load(const std::filesystem::path& path);
    void clear();

private:
    Observation& slot(const MatchContext& ctx);  // krever at mutex_ holdes

    std::atomic<bool> enabled_;
    mutable std::mutex mutex_;
    std::map<ObservationKey, Observation> obs_;
    Observation overflow_;  // mål for skriving når tabellen er full (data kastes)
};

}  // namespace aifw
