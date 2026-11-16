// Kobler DecisionCoordinator sine "persistente blokkeringer" til WFP + regelfilen.
// AI-blokkeringer lagres som regel (source="ai", persistent=true) i rules.json slik at
// regelfilen forblir eneste kilde til sannhet – WFP synkroniseres fra den ved oppstart.
#pragma once
#ifdef _WIN32

#include <filesystem>
#include <mutex>

#include "DecisionCoordinator.hpp"
#include "RuleEngine.hpp"
#include "WfpManager.hpp"

namespace aifw {

class WfpRuleSink final : public IPersistentRuleSink {
public:
    WfpRuleSink(WfpManager& wfp, std::filesystem::path rulesPath) : wfp_(wfp), rulesPath_(std::move(rulesPath)) {}
    /// Settes etter at FirewallCore er opprettet (kjernen tar sink-pekeren i konstruktøren).
    void attach(RuleEngine* rules) { rules_ = rules; }

    void persistBlock(const FlowKey& key, const std::string& appPath, const std::string& reason) override;

private:
    WfpManager& wfp_;
    std::filesystem::path rulesPath_;
    RuleEngine* rules_{nullptr};
    std::mutex mutex_;
};

}  // namespace aifw
#endif  // _WIN32
