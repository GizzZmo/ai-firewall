// Asynkron AI-inferens. Pakkeveien legger kun forespørsler i en begrenset kø og
// returnerer umiddelbart; arbeidertråder batcher og kjører modellen.
#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "Config.hpp"
#include "FeatureSchema.hpp"
#include "Model.hpp"
#include "Types.hpp"

namespace aifw {

struct InferenceResult {
    FlowKey key;
    bool ok{false};               // false = modellfeil; kalleren skal falle tilbake (fail-safe)
    float score{0.0f};            // sannsynlighet for ondsinnet
    Verdict verdict{Verdict::Unknown};  // Block/Allow ved sikker score, Unknown i gråsonen
    std::string error;
};

using InferenceCallback = std::function<void(const InferenceResult&)>;

struct AiStats {
    std::uint64_t submitted{0};
    std::uint64_t completed{0};
    std::uint64_t rejectedQueueFull{0};
    std::uint64_t errors{0};
    std::uint64_t blocks{0};
    std::size_t queueDepth{0};
    bool healthy{true};
};

class AIDecisionEngine {
public:
    AIDecisionEngine(std::unique_ptr<IModel> model, AiConfig cfg);
    ~AIDecisionEngine();  // stopper og joiner arbeidertråder (RAII)
    AIDecisionEngine(const AIDecisionEngine&) = delete;
    AIDecisionEngine& operator=(const AIDecisionEngine&) = delete;

    /// Ikke-blokkerende. Returnerer false hvis køen er full, motoren er stoppet
    /// eller circuit breaker er åpen. Callback kalles fra en arbeidertråd.
    bool submit(const FlowKey& key, const FeatureVector& features, InferenceCallback cb);

    /// Kan AI brukes nå? (false når circuit breaker er åpen etter gjentatte feil)
    [[nodiscard]] bool healthy() const noexcept;
    [[nodiscard]] AiStats stats() const;
    [[nodiscard]] std::string modelName() const;
    [[nodiscard]] Verdict classify(float score) const noexcept;

    void stop();  // idempotent

private:
    struct Request {
        FlowKey key;
        FeatureVector features;
        InferenceCallback cb;
    };

    void workerLoop(std::stop_token st);
    void recordFailure(const std::string& what);
    void recordSuccess();

    std::unique_ptr<IModel> model_;
    const AiConfig cfg_;

    mutable std::mutex mutex_;
    std::condition_variable_any cv_;
    std::deque<Request> queue_;
    bool stopped_{false};

    std::atomic<std::uint64_t> submitted_{0}, completed_{0}, rejected_{0}, errors_{0}, blocks_{0};
    std::atomic<std::uint32_t> consecutiveErrors_{0};
    std::atomic<std::int64_t> breakerOpenUntilNs_{0};  // steady_clock-tid; 0 = lukket

    std::vector<std::jthread> workers_;  // sist: destrueres først (joines før resten forsvinner)
};

}  // namespace aifw
