#ifdef _WIN32
#include "ServiceHost.hpp"

#include <spdlog/spdlog.h>

#include "Log.hpp"

namespace aifw {

ServiceHost::ServiceHost(std::filesystem::path baseDir) : baseDir_(std::move(baseDir)) {
    cfg_ = Config::loadFromFile(baseDir_ / "config" / "config.json");
    initLogging(cfg_.logLevel, baseDir_ / cfg_.logFile);
    spdlog::info("AI-Firewall starter fra {}", baseDir_.string());

    if (cfg_.wfp.enabled) {
        try {
            wfp_ = std::make_unique<WfpManager>();
            wfp_->install();
            sink_ = std::make_unique<WfpRuleSink>(*wfp_, baseDir_ / cfg_.rulesPath);
        } catch (const std::exception& e) {
            // Uten WFP mister vi persistente regler, men WinDivert-filtreringen virker fortsatt.
            spdlog::error("WFP utilgjengelig: {} – fortsetter uten persistente regler", e.what());
            sink_.reset();
            wfp_.reset();
        }
    }

    core_ = std::make_unique<FirewallCore>(cfg_, baseDir_, nullptr, sink_.get());
    if (sink_) sink_->attach(&core_->rules());
    if (wfp_ && cfg_.wfp.syncPersistentRules) {
        try {
            wfp_->syncPersistentRules(core_->rules().rules());
        } catch (const std::exception& e) {
            spdlog::error("WFP-synk feilet: {}", e.what());
        }
    }

    pipe_ = std::make_unique<PipeServer>(cfg_.pipeName, [this](const nlohmann::json& cmd, bool admin) {
        auto reply = core_->handleCommand(cmd, admin);
        // Etter reload/apply: hold WFP i takt med regelfilen.
        const auto name = cmd.value("cmd", std::string());
        if (wfp_ && reply.value("ok", false) && (name == "reload_rules" || name == "apply_suggestions"))
            wfp_->syncPersistentRules(core_->rules().rules());
        return reply;
    });
    core_->addNotifier(std::make_unique<PipeNotifier>(*pipe_));

    if (cfg_.windivert.trackProcesses) resolver_ = std::make_unique<ProcessResolver>();
    engine_ = std::make_unique<PacketEngine>(
        cfg_.windivert, [this](const PacketInfo& p) { return core_->decide(p); }, resolver_.get());
}

ServiceHost::~ServiceHost() { stop(); }

void ServiceHost::start() {
    core_->startHousekeeping();
    pipe_->start();
    if (resolver_) {
        try {
            resolver_->start();
        } catch (const std::exception& e) {
            // Ikke reset(): PacketEngine holder pekeren. Et ikke-startet resolver gir bare tomme oppslag.
            spdlog::warn("ProcessResolver kunne ikke starte: {} – app-regler matcher ikke", e.what());
        }
    }
    engine_->start();  // kaster hvis WinDivert ikke kan åpnes – da feiler tjenestestart
    spdlog::info("AI-Firewall kjører (læringsmodus: {})", core_->learning().enabled() ? "på" : "av");
}

void ServiceHost::stop() {
    // Rekkefølge: slutt å ta imot pakker -> stopp app-oppslag -> IPC -> kjerne (AI, lagring).
    if (engine_) engine_->stop();
    if (resolver_) resolver_->stop();
    if (pipe_) pipe_->stop();
    if (core_) core_->stop();
    spdlog::info("AI-Firewall stoppet");
    spdlog::default_logger()->flush();
}

}  // namespace aifw
#endif  // _WIN32
