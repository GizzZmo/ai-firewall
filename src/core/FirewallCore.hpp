// Plattformuavhengig kjerne som eier alle komponentene og kobler dem sammen.
// Windows-tjenesten legger på PacketEngine (WinDivert), WfpManager og PipeServer.
#pragma once

#include <filesystem>
#include <memory>
#include <thread>

#include <nlohmann/json_fwd.hpp>

#include "AIDecisionEngine.hpp"
#include "Config.hpp"
#include "DecisionCoordinator.hpp"
#include "FlowExporter.hpp"
#include "FlowTracker.hpp"
#include "GeoIpLookup.hpp"
#include "HostTracker.hpp"
#include "LearningMode.hpp"
#include "Notifier.hpp"
#include "RuleEngine.hpp"
#include "VerdictCache.hpp"

namespace aifw {

class FirewallCore {
public:
    /// baseDir brukes for relative stier i konfig. model == nullptr => createModel(cfg.ai).
    FirewallCore(Config cfg, std::filesystem::path baseDir, std::unique_ptr<IModel> model = nullptr,
                 IPersistentRuleSink* sink = nullptr);
    ~FirewallCore();
    FirewallCore(const FirewallCore&) = delete;
    FirewallCore& operator=(const FirewallCore&) = delete;

    /// Starter bakgrunnstråd for utløp av flyter og lagring av læringsdata.
    void startHousekeeping(std::chrono::milliseconds interval = std::chrono::seconds(5));
    void stop();

    Decision decide(const PacketInfo& pkt, TimePoint now = Clock::now()) { return coordinator_->decide(pkt, now); }
    void housekeeping(TimePoint now = Clock::now());

    /// Håndterer en IPC-kommando. clientIsAdmin styrer om tilstandsendringer er lov.
    nlohmann::json handleCommand(const nlohmann::json& cmd, bool clientIsAdmin);
    [[nodiscard]] nlohmann::json statusJson() const;

    void addNotifier(std::unique_ptr<INotifier> n) { notifier_.add(std::move(n)); }
    void reloadRules();
    /// Laster modell på nytt. Hvis path er satt, oppdateres cfg.ai.modelPath først.
    void reloadModel(const std::string& path = {});

    [[nodiscard]] const Config& config() const noexcept { return cfg_; }
    [[nodiscard]] RuleEngine& rules() noexcept { return rules_; }
    [[nodiscard]] LearningMode& learning() noexcept { return learning_; }
    [[nodiscard]] FlowTracker& flows() noexcept { return flows_; }
    [[nodiscard]] HostTracker& hosts() noexcept { return hosts_; }
    [[nodiscard]] DecisionCoordinator& coordinator() noexcept { return *coordinator_; }
    [[nodiscard]] AIDecisionEngine* ai() noexcept { return ai_.get(); }
    [[nodiscard]] const MemoryNotifier& recentEvents() const noexcept { return *recent_; }
    [[nodiscard]] std::filesystem::path resolve(const std::string& p) const;

private:
    Config cfg_;
    std::filesystem::path baseDir_;
    CompositeNotifier notifier_;
    MemoryNotifier* recent_{nullptr};  // eies av notifier_
    RuleEngine rules_;
    FlowTracker flows_;
    HostTracker hosts_;
    VerdictCache cache_;
    LearningMode learning_;
    std::unique_ptr<FlowExporter> exporter_;
    std::unique_ptr<GeoIpLookup> geoip_;
    std::unique_ptr<AIDecisionEngine> ai_;
    std::unique_ptr<DecisionCoordinator> coordinator_;  // etter ai_: destrueres før ai_
    TimePoint lastLearningSave_{Clock::now()};
    std::jthread housekeeper_;  // sist: stoppes og joines først
};

}  // namespace aifw
