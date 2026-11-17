#include "Config.hpp"

#include <fstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace aifw {
using nlohmann::json;

namespace {
template <typename T>
void read(const json& j, const char* key, T& out) {
    if (j.contains(key) && !j[key].is_null()) out = j[key].get<T>();
}
template <typename Dur>
void readDur(const json& j, const char* key, Dur& out) {
    if (j.contains(key)) out = Dur(j[key].get<std::int64_t>());
}
Verdict parseVerdict(const std::string& s) {
    if (s == "allow") return Verdict::Allow;
    if (s == "block" || s == "deny") return Verdict::Block;
    throw std::runtime_error("default_verdict må være allow eller block");
}
}  // namespace

Config Config::fromJson(const json& j) {
    Config c;
    read(j, "log_level", c.logLevel);
    read(j, "log_file", c.logFile);
    read(j, "rules_path", c.rulesPath);
    read(j, "learning_path", c.learningPath);
    read(j, "pipe_name", c.pipeName);
    read(j, "learning_mode", c.learningMode);
    if (j.contains("default_verdict")) c.defaultVerdict = parseVerdict(j["default_verdict"].get<std::string>());

    if (j.contains("ai")) {
        const auto& a = j["ai"];
        read(a, "enabled", c.ai.enabled);
        read(a, "model_path", c.ai.modelPath);
        read(a, "input_name", c.ai.inputName);
        read(a, "output_name", c.ai.outputName);
        read(a, "output_class_index", c.ai.outputClassIndex);
        read(a, "worker_threads", c.ai.workerThreads);
        read(a, "queue_capacity", c.ai.queueCapacity);
        read(a, "max_batch", c.ai.maxBatch);
        read(a, "block_threshold", c.ai.blockThreshold);
        read(a, "allow_threshold", c.ai.allowThreshold);
        read(a, "min_packets_before_inference", c.ai.minPacketsBeforeInference);
        read(a, "reevaluate_every_packets", c.ai.reevaluateEveryPackets);
        read(a, "max_consecutive_errors", c.ai.maxConsecutiveErrors);
        readDur(a, "error_cooldown_sec", c.ai.errorCooldown);
    }
    if (j.contains("cache")) {
        const auto& a = j["cache"];
        readDur(a, "allow_ttl_sec", c.cache.allowTtl);
        readDur(a, "block_ttl_sec", c.cache.blockTtl);
        read(a, "max_entries", c.cache.maxEntries);
    }
    if (j.contains("flow")) {
        const auto& a = j["flow"];
        readDur(a, "tcp_idle_timeout_ms", c.flow.tcpIdleTimeout);
        readDur(a, "udp_idle_timeout_ms", c.flow.udpIdleTimeout);
        readDur(a, "closed_timeout_ms", c.flow.closedTimeout);
        readDur(a, "other_idle_timeout_ms", c.flow.otherIdleTimeout);
        read(a, "max_flows", c.flow.maxFlows);
        read(a, "entropy_sample_packets", c.flow.entropySamplePackets);
    }
    if (j.contains("host")) {
        const auto& a = j["host"];
        read(a, "enabled", c.host.enabled);
        readDur(a, "window_sec", c.host.window);
        read(a, "max_unique_ports", c.host.maxUniquePorts);
        read(a, "max_new_flows", c.host.maxNewFlows);
        read(a, "max_syns", c.host.maxSyns);
    }
    if (j.contains("windivert")) {
        const auto& a = j["windivert"];
        read(a, "filter", c.windivert.filter);
        read(a, "priority", c.windivert.priority);
        read(a, "queue_length", c.windivert.queueLength);
        read(a, "queue_time_ms", c.windivert.queueTimeMs);
        read(a, "queue_size_bytes", c.windivert.queueSizeBytes);
        read(a, "batch_size", c.windivert.batchSize);
        read(a, "worker_threads", c.windivert.workerThreads);
        read(a, "track_processes", c.windivert.trackProcesses);
        read(a, "inject_reject_on_block", c.windivert.injectRejectOnBlock);
    }
    if (j.contains("wfp")) {
        const auto& a = j["wfp"];
        read(a, "enabled", c.wfp.enabled);
        read(a, "persist_ai_blocks", c.wfp.persistAiBlocks);
        read(a, "sync_persistent_rules", c.wfp.syncPersistentRules);
    }
    c.validate();
    return c;
}

Config Config::loadFromFile(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("kan ikke åpne konfig: " + path.string());
    return fromJson(json::parse(in, nullptr, true, /*ignore_comments=*/true));
}

void Config::validate() const {
    auto fail = [](const std::string& m) { throw std::runtime_error("ugyldig konfig: " + m); };
    if (ai.blockThreshold <= 0.0 || ai.blockThreshold > 1.0) fail("ai.block_threshold må være i (0,1]");
    if (ai.allowThreshold < 0.0 || ai.allowThreshold >= ai.blockThreshold) fail("ai.allow_threshold må være i [0, block_threshold)");
    if (ai.workerThreads == 0 || ai.workerThreads > 64) fail("ai.worker_threads må være 1-64");
    if (ai.queueCapacity == 0) fail("ai.queue_capacity må være > 0");
    if (ai.maxBatch == 0) fail("ai.max_batch må være > 0");
    if (windivert.batchSize == 0 || windivert.batchSize > 255) fail("windivert.batch_size må være 1-255");
    if (windivert.workerThreads == 0 || windivert.workerThreads > 64) fail("windivert.worker_threads må være 1-64");
    if (windivert.priority < -30000 || windivert.priority > 30000) fail("windivert.priority må være i [-30000, 30000]");
    if (windivert.queueLength < 32 || windivert.queueLength > 16384) fail("windivert.queue_length må være 32-16384");
    if (windivert.queueTimeMs < 100 || windivert.queueTimeMs > 16000) fail("windivert.queue_time_ms må være 100-16000");
    if (flow.maxFlows == 0) fail("flow.max_flows må være > 0");
    if (host.window.count() <= 0) fail("host.window_sec må være > 0");
    if (pipeName.empty() || pipeName.find_first_of("\\/") != std::string::npos) fail("pipe_name kan ikke inneholde skråstrek");
}

json Config::toJson() const {
    return json{
        {"log_level", logLevel},
        {"log_file", logFile},
        {"rules_path", rulesPath},
        {"learning_path", learningPath},
        {"pipe_name", pipeName},
        {"default_verdict", std::string(toString(defaultVerdict))},
        {"learning_mode", learningMode},
        {"ai",
         {{"enabled", ai.enabled},
          {"model_path", ai.modelPath},
          {"input_name", ai.inputName},
          {"output_name", ai.outputName},
          {"output_class_index", ai.outputClassIndex},
          {"worker_threads", ai.workerThreads},
          {"queue_capacity", ai.queueCapacity},
          {"max_batch", ai.maxBatch},
          {"block_threshold", ai.blockThreshold},
          {"allow_threshold", ai.allowThreshold},
          {"min_packets_before_inference", ai.minPacketsBeforeInference},
          {"reevaluate_every_packets", ai.reevaluateEveryPackets},
          {"max_consecutive_errors", ai.maxConsecutiveErrors},
          {"error_cooldown_sec", ai.errorCooldown.count()}}},
        {"cache",
         {{"allow_ttl_sec", cache.allowTtl.count()},
          {"block_ttl_sec", cache.blockTtl.count()},
          {"max_entries", cache.maxEntries}}},
        {"flow",
         {{"tcp_idle_timeout_ms", flow.tcpIdleTimeout.count()},
          {"udp_idle_timeout_ms", flow.udpIdleTimeout.count()},
          {"closed_timeout_ms", flow.closedTimeout.count()},
          {"other_idle_timeout_ms", flow.otherIdleTimeout.count()},
          {"max_flows", flow.maxFlows},
          {"entropy_sample_packets", flow.entropySamplePackets}}},
        {"host",
         {{"enabled", host.enabled},
          {"window_sec", host.window.count()},
          {"max_unique_ports", host.maxUniquePorts},
          {"max_new_flows", host.maxNewFlows},
          {"max_syns", host.maxSyns}}},
        {"windivert",
         {{"filter", windivert.filter},
          {"priority", windivert.priority},
          {"queue_length", windivert.queueLength},
          {"queue_time_ms", windivert.queueTimeMs},
          {"queue_size_bytes", windivert.queueSizeBytes},
          {"batch_size", windivert.batchSize},
          {"worker_threads", windivert.workerThreads},
          {"track_processes", windivert.trackProcesses},
          {"inject_reject_on_block", windivert.injectRejectOnBlock}}},
        {"wfp",
         {{"enabled", wfp.enabled},
          {"persist_ai_blocks", wfp.persistAiBlocks},
          {"sync_persistent_rules", wfp.syncPersistentRules}}},
    };
}

}  // namespace aifw
