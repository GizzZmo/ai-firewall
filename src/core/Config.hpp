// Konfigurasjon lastet fra config.json. Alle felter har trygge standardverdier.
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>

#include <nlohmann/json_fwd.hpp>

#include "FlowTracker.hpp"
#include "HostTracker.hpp"
#include "Types.hpp"

namespace aifw {

struct AiConfig {
    bool enabled{true};
    std::string modelPath{"models/flow_classifier.onnx"};
    std::string inputName;         // tom = første input i modellen
    std::string outputName;        // tom = output nr. 1 (sannsynligheter fra skl2onnx), ellers 0
    std::size_t outputClassIndex{1};  // kolonne i [N,2]-output som er "ondsinnet"
    std::size_t workerThreads{2};
    std::size_t queueCapacity{4096};
    std::size_t maxBatch{32};
    double blockThreshold{0.90};   // score >= dette => block
    double allowThreshold{0.30};   // score <= dette => allow (cache)
    std::uint32_t minPacketsBeforeInference{4};
    std::uint32_t reevaluateEveryPackets{64};
    std::uint32_t maxConsecutiveErrors{5};  // circuit breaker
    std::chrono::seconds errorCooldown{30};
};

struct CacheConfig {
    std::chrono::seconds allowTtl{300};
    std::chrono::seconds blockTtl{900};
    std::size_t maxEntries{100'000};
};

struct WinDivertConfig {
    // Standard: alt unntatt loopback. Se README for filter-syntaks.
    std::string filter{"!loopback and (tcp or udp or icmp or icmpv6)"};
    std::int16_t priority{0};
    std::uint64_t queueLength{8192};
    std::uint64_t queueTimeMs{2000};
    std::uint64_t queueSizeBytes{4 * 1024 * 1024};
    std::size_t batchSize{16};      // pakker per WinDivertRecvEx
    std::size_t workerThreads{2};
    bool trackProcesses{true};      // eget FLOW-lag-håndtak for prosess-ID/app-sti
    bool injectRejectOnBlock{true}; // send TCP RST / ICMP unreachable ved blokkering
};

struct WfpConfig {
    bool enabled{true};
    bool persistAiBlocks{false};    // legg AI-blokkeringer inn som persistente WFP-regler
    bool syncPersistentRules{true}; // legg regler med "persistent": true inn i WFP ved oppstart
};

struct Config {
    std::string logLevel{"info"};
    std::string logFile{"logs/aifw.log"};
    std::string rulesPath{"config/rules.json"};
    std::string learningPath{"data/learning.json"};
    std::string pipeName{"aifw"};  // \\.\pipe\aifw
    Verdict defaultVerdict{Verdict::Allow};  // når verken regel, cache eller AI har svar
    bool learningMode{false};
    AiConfig ai;
    CacheConfig cache;
    FlowTrackerConfig flow;
    HostTrackerConfig host;
    WinDivertConfig windivert;
    WfpConfig wfp;

    static Config fromJson(const nlohmann::json& j);
    static Config loadFromFile(const std::filesystem::path& path);
    [[nodiscard]] nlohmann::json toJson() const;
    /// Kaster std::runtime_error ved inkonsistente verdier.
    void validate() const;
};

}  // namespace aifw
