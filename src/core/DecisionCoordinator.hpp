// Kombinerer regelmotor, verdikt-cache, AI, læringsmodus og vertsnivå-deteksjon til én beslutning per pakke.
//
// Rekkefølge (rask sti først – pakkeveien skal aldri vente på AI):
//   1. Eksplisitt regel (RuleEngine)            -> verdikt umiddelbart
//   2. Cachet verdikt for flyten (VerdictCache) -> verdikt umiddelbart
//   3. Vertsnivå-alarm (HostTracker)            -> block hvis terskel overskredet
//   4. Standardverdikt + asynkron AI-vurdering  -> AI-svaret havner i cachen og
//      gjelder fra neste pakke i flyten
// Ved AI-feil / åpen circuit breaker / full kø brukes kun 1+2+standard (fail-safe).
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

#include "AIDecisionEngine.hpp"
#include "Config.hpp"
#include "FlowTracker.hpp"
#include "HostTracker.hpp"
#include "LearningMode.hpp"
#include "Notifier.hpp"
#include "RuleEngine.hpp"
#include "VerdictCache.hpp"

namespace aifw {

enum class DecisionSource { Rule, Cache, Default, AiPending, FailSafe, Learning, Host, Invalid };
std::string_view toString(DecisionSource s) noexcept;

struct Decision {
    Verdict verdict{Verdict::Allow};
    DecisionSource source{DecisionSource::Default};
    std::string ruleId;  // satt når source == Rule
};

/// Mottaker for persistente blokkeringer (implementeres av WfpManager-adapter på Windows).
class IPersistentRuleSink {
public:
    virtual ~IPersistentRuleSink() = default;
    virtual void persistBlock(const FlowKey& key, const std::string& appPath, const std::string& reason) = 0;
};

struct CoordinatorStats {
    std::uint64_t packets{0}, allowed{0}, blocked{0}, ruleHits{0}, cacheHits{0}, aiSubmitted{0}, failSafe{0},
        wouldBlock{0}, hostBlocks{0};
};

class DecisionCoordinator {
public:
    /// Ikke-eiende referanser: eierskapet ligger i FirewallService (lever lengre enn denne).
    /// ai og sink kan være nullptr (AI avslått / ingen WFP).
    DecisionCoordinator(const Config& cfg, RuleEngine& rules, FlowTracker& flows, HostTracker& hosts,
                        VerdictCache& cache, AIDecisionEngine* ai, LearningMode& learning, INotifier& notifier,
                        IPersistentRuleSink* sink = nullptr);
    ~DecisionCoordinator();
    DecisionCoordinator(const DecisionCoordinator&) = delete;
    DecisionCoordinator& operator=(const DecisionCoordinator&) = delete;

    /// Hovedinngang fra pakkeveien. Tråd-sikker, O(1) forventet, ingen blokkering på AI.
    Decision decide(const PacketInfo& pkt, TimePoint now = Clock::now());

    void setLearningMode(bool on);
    [[nodiscard]] bool learningMode() const noexcept { return learning_.enabled(); }
    [[nodiscard]] CoordinatorStats stats() const noexcept;

    /// Sletter cache (f.eks. etter at regler er endret).
    void invalidateCache() { cache_.clear(); }

private:
    void onInference(const InferenceResult& r, const MatchContext& ctx);
    bool markPending(const FlowKey& k);
    void clearPending(const FlowKey& k);

    const Config& cfg_;
    RuleEngine& rules_;
    FlowTracker& flows_;
    HostTracker& hosts_;
    VerdictCache& cache_;
    AIDecisionEngine* ai_;
    LearningMode& learning_;
    INotifier& notifier_;
    IPersistentRuleSink* sink_;

    std::mutex pendingMutex_;
    std::unordered_set<FlowKey, FlowKeyHash> pending_;  // flyter med inferens underveis
    std::atomic<bool> aiWasHealthy_{true};

    std::atomic<std::uint64_t> packets_{0}, allowed_{0}, blocked_{0}, ruleHits_{0}, cacheHits_{0}, aiSubmitted_{0},
        failSafe_{0}, wouldBlock_{0}, hostBlocks_{0};
    // Teller for callbacks som fortsatt kjører, slik at destruktøren kan vente på dem.
    std::atomic<int> inFlight_{0};
};

}  // namespace aifw
