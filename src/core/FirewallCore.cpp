#include "FirewallCore.hpp"

#include <condition_variable>
#include <mutex>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "IpcProtocol.hpp"

namespace aifw {
using nlohmann::json;

FirewallCore::FirewallCore(Config cfg, std::filesystem::path baseDir, std::unique_ptr<IModel> model,
                           IPersistentRuleSink* sink)
    : cfg_(std::move(cfg)),
      baseDir_(std::move(baseDir)),
      flows_(cfg_.flow),
      hosts_(cfg_.host),
      cache_(cfg_.cache.maxEntries),
      learning_(cfg_.learningMode) {
    notifier_.add(std::make_unique<LogNotifier>());
    auto recent = std::make_unique<MemoryNotifier>(500);
    recent_ = recent.get();
    notifier_.add(std::move(recent));

    exporter_ = std::make_unique<FlowExporter>(resolve("data/flows_export.jsonl"));

    if (cfg_.geoip.enabled) {
        geoip_ = std::make_unique<GeoIpLookup>(resolve(cfg_.geoip.mmdbPath).string());
    }

    try {
        rules_.loadFromFile(resolve(cfg_.rulesPath));
        spdlog::info("Lastet {} regler fra {}", rules_.size(), resolve(cfg_.rulesPath).string());
    } catch (const std::exception& e) {
        spdlog::error("Kunne ikke laste regler: {} – fortsetter uten eksplisitte regler", e.what());
    }
    try {
        learning_.load(resolve(cfg_.learningPath));
    } catch (const std::exception& e) {
        spdlog::warn("Kunne ikke laste læringsdata: {}", e.what());
    }

    if (cfg_.ai.enabled) {
        if (!model) model = createModel(cfg_.ai, baseDir_);
        ai_ = std::make_unique<AIDecisionEngine>(std::move(model), cfg_.ai);
    } else {
        spdlog::warn("AI er avslått i konfig – kun regelmotor");
    }
    coordinator_ = std::make_unique<DecisionCoordinator>(cfg_, rules_, flows_, hosts_, cache_, ai_.get(), learning_,
                                                         notifier_, sink, geoip_.get());
}

FirewallCore::~FirewallCore() { stop(); }

void FirewallCore::stop() {
    if (housekeeper_.joinable()) {
        housekeeper_.request_stop();
        housekeeper_.join();
    }
    if (ai_) ai_->stop();
    if (exporter_) exporter_->flush();
    try {
        if (learning_.enabled() || !learning_.snapshot().empty()) learning_.save(resolve(cfg_.learningPath));
    } catch (const std::exception& e) {
        spdlog::warn("Kunne ikke lagre læringsdata: {}", e.what());
    }
}

std::filesystem::path FirewallCore::resolve(const std::string& p) const {
    std::filesystem::path path(p);
    return path.is_relative() && !baseDir_.empty() ? baseDir_ / path : path;
}

void FirewallCore::startHousekeeping(std::chrono::milliseconds interval) {
    housekeeper_ = std::jthread([this, interval](std::stop_token st) {
        std::mutex m;
        std::condition_variable_any cv;
        std::unique_lock lock(m);
        while (!st.stop_requested()) {
            cv.wait_for(lock, st, interval, [] { return false; });
            if (st.stop_requested()) break;
            try {
                housekeeping();
            } catch (const std::exception& e) {
                spdlog::error("housekeeping feilet: {}", e.what());
            }
        }
    });
}

void FirewallCore::housekeeping(TimePoint now) {
    const auto removed = flows_.expire(now, [this](const FlowKey& k, const FlowStats& s) {
        if (exporter_) exporter_->onExpired(k, s);
    });
    if (removed) spdlog::debug("Fjernet {} utløpte flyter ({} aktive)", removed, flows_.size());
    hosts_.expire(now);
    if (learning_.enabled() && now - lastLearningSave_ > std::chrono::minutes(1)) {
        learning_.save(resolve(cfg_.learningPath));
        lastLearningSave_ = now;
    }
}

void FirewallCore::reloadRules() {
    rules_.loadFromFile(resolve(cfg_.rulesPath));
    coordinator_->invalidateCache();
    spdlog::info("Regler lastet på nytt: {} regler", rules_.size());
}

void FirewallCore::reloadModel(const std::string& path) {
    if (!ai_ || !cfg_.ai.enabled) {
        spdlog::warn("Kan ikke laste modell på nytt: AI er ikke aktiv");
        return;
    }
    if (!path.empty()) cfg_.ai.modelPath = path;
    try {
        auto newModel = createModel(cfg_.ai, baseDir_);
        ai_->setModel(std::move(newModel));
        spdlog::info("Modell lastet på nytt: {}", cfg_.ai.modelPath);
        if (coordinator_) coordinator_->invalidateCache();
    } catch (const std::exception& e) {
        spdlog::error("Feil ved reload av modell: {}", e.what());
    }
}

json FirewallCore::statusJson() const {
    const auto s = coordinator_->stats();
    json j{{"learning_mode", learning_.enabled()},
           {"rules", rules_.size()},
           {"active_flows", flows_.size()},
           {"tracked_hosts", hosts_.size()},
           {"dropped_new_flows", flows_.droppedNewFlows()},
           {"packets", s.packets},
           {"allowed", s.allowed},
           {"blocked", s.blocked},
           {"rule_hits", s.ruleHits},
           {"cache_hits", s.cacheHits},
           {"ai_submitted", s.aiSubmitted},
           {"fail_safe", s.failSafe},
           {"would_block", s.wouldBlock},
           {"host_blocks", s.hostBlocks}};
    if (ai_) {
        const auto a = ai_->stats();
        j["ai"] = {{"model", ai_->modelName()}, {"healthy", a.healthy},     {"queue_depth", a.queueDepth},
                   {"completed", a.completed},  {"errors", a.errors},       {"rejected", a.rejectedQueueFull},
                   {"blocks", a.blocks}};
    } else {
        j["ai"] = nullptr;
    }
    return j;
}

json FirewallCore::handleCommand(const json& msg, bool clientIsAdmin) {
    const std::string cmd = msg.value("cmd", std::string());
    if (cmd.empty()) return ipc::makeError("", "mangler 'cmd'");
    if (ipc::isMutatingCommand(cmd) && !clientIsAdmin) return ipc::makeError(cmd, "krever administrator");
    try {
        if (cmd == "ping") return ipc::makeReply(cmd, true);
        if (cmd == "get_status") return ipc::makeReply(cmd, true, {{"status", statusJson()}});
        if (cmd == "get_events") {
            json arr = json::array();
            for (const auto& e : recent_->events()) arr.push_back(e.toJson());
            return ipc::makeReply(cmd, true, {{"events", arr}});
        }
        if (cmd == "set_learning") {
            if (!msg.contains("enabled") || !msg["enabled"].is_boolean()) return ipc::makeError(cmd, "'enabled' må være bool");
            coordinator_->setLearningMode(msg["enabled"].get<bool>());
            return ipc::makeReply(cmd, true, {{"learning_mode", learning_.enabled()}});
        }
        if (cmd == "get_suggestions") {
            json arr = json::array();
            for (const auto& r : learning_.suggestRules()) arr.push_back(RuleEngine::ruleToJson(r));
            return ipc::makeReply(cmd, true, {{"rules", arr}});
        }
        if (cmd == "apply_suggestions") {
            std::size_t n = 0;
            for (auto& r : learning_.suggestRules()) {
                rules_.addRule(std::move(r));
                ++n;
            }
            rules_.saveToFile(resolve(cfg_.rulesPath));
            coordinator_->invalidateCache();
            return ipc::makeReply(cmd, true, {{"applied", n}});
        }
        if (cmd == "reload_rules") {
            reloadRules();
            return ipc::makeReply(cmd, true, {{"rules", rules_.size()}});
        }
        if (cmd == "reload_model") {
            const std::string path = msg.value("path", std::string());
            reloadModel(path);
            return ipc::makeReply(cmd, true, {{"model", cfg_.ai.modelPath}, {"name", ai_ ? ai_->modelName() : std::string()}});
        }
    } catch (const std::exception& e) {
        return ipc::makeError(cmd, e.what());
    }
    return ipc::makeError(cmd, "ukjent kommando");
}

}  // namespace aifw
