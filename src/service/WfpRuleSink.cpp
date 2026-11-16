#ifdef _WIN32
#include "WfpRuleSink.hpp"

#include <spdlog/spdlog.h>

namespace aifw {

void WfpRuleSink::persistBlock(const FlowKey& key, const std::string& appPath, const std::string& reason) {
    std::lock_guard lock(mutex_);
    Rule r;
    r.id = "ai-block-" + key.remoteIp.toString() + "-" + std::to_string(key.remotePort) + "-" +
           std::string(toString(key.protocol));
    r.action = Verdict::Block;
    r.direction = Direction::Any;
    r.protocol = key.protocol;
    r.remoteIps = {Cidr{key.remoteIp, static_cast<std::uint8_t>(key.remoteIp.version == 6 ? 128 : 32)}};
    r.remotePorts = {PortRange{key.remotePort, key.remotePort}};
    // Bevisst IKKE app-spesifikk: en ondsinnet motpart blokkeres for alle apper.
    r.priority = 80;
    r.persistent = true;
    r.source = "ai";
    r.comment = "Automatisk: " + reason + (appPath.empty() ? "" : " (app: " + appPath + ")");

    if (rules_) {
        rules_->addRule(r);
        try {
            rules_->saveToFile(rulesPath_);
        } catch (const std::exception& e) {
            spdlog::error("kunne ikke lagre regelfil: {}", e.what());
        }
    }
    for (const auto& w : WfpRule::fromRule(r)) wfp_.addRule(w);
    spdlog::warn("Persistent AI-blokkering lagt inn: {}", r.id);
}

}  // namespace aifw
#endif  // _WIN32
