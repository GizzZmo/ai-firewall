#include "AIDecisionEngine.hpp"

#include <spdlog/spdlog.h>

namespace aifw {

namespace {
std::int64_t nowNs() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
}
}  // namespace

AIDecisionEngine::AIDecisionEngine(std::unique_ptr<IModel> model, AiConfig cfg)
    : model_(std::move(model)), cfg_(cfg) {
    if (!model_) throw std::invalid_argument("AIDecisionEngine krever en modell");
    workers_.reserve(cfg_.workerThreads);
    for (std::size_t i = 0; i < cfg_.workerThreads; ++i)
        workers_.emplace_back([this](std::stop_token st) { workerLoop(st); });
    spdlog::info("AIDecisionEngine startet: modell={}, tråder={}, kø={}, block>={}, allow<={}", model_->name(),
                 cfg_.workerThreads, cfg_.queueCapacity, cfg_.blockThreshold, cfg_.allowThreshold);
}

AIDecisionEngine::~AIDecisionEngine() { stop(); }

void AIDecisionEngine::stop() {
    {
        std::lock_guard lock(mutex_);
        if (stopped_) return;
        stopped_ = true;
    }
    for (auto& w : workers_) w.request_stop();
    cv_.notify_all();
    for (auto& w : workers_)
        if (w.joinable()) w.join();
    // Forespørsler som aldri ble behandlet får et "ikke ok"-svar så ingen venter evig.
    std::deque<Request> leftover;
    {
        std::lock_guard lock(mutex_);
        leftover.swap(queue_);
    }
    for (auto& r : leftover) {
        if (r.cb) r.cb(InferenceResult{r.key, false, 0.0f, Verdict::Unknown, "motoren stoppet"});
    }
}

void AIDecisionEngine::setModel(std::unique_ptr<IModel> model) {
    if (!model) {
        spdlog::error("setModel: null modell ignorert");
        return;
    }
    std::shared_ptr<IModel> shared(std::move(model));
    std::string name = shared->name();
    {
        std::lock_guard lock(mutex_);
        model_ = std::move(shared);
    }
    spdlog::info("Modell byttet til: {}", name);
}

bool AIDecisionEngine::healthy() const noexcept {
    const auto until = breakerOpenUntilNs_.load(std::memory_order_acquire);
    return until == 0 || nowNs() >= until;
}

Verdict AIDecisionEngine::classify(float score) const noexcept {
    if (score >= cfg_.blockThreshold) return Verdict::Block;
    if (score <= cfg_.allowThreshold) return Verdict::Allow;
    return Verdict::Unknown;  // usikker: ikke la AI alene avgjøre
}

bool AIDecisionEngine::submit(const FlowKey& key, const FeatureVector& features, InferenceCallback cb) {
    if (!healthy()) return false;
    {
        std::lock_guard lock(mutex_);
        if (stopped_) return false;
        if (queue_.size() >= cfg_.queueCapacity) {
            rejected_.fetch_add(1, std::memory_order_relaxed);
            return false;  // mottrykk: heller ingen AI-vurdering enn å blokkere pakkeveien
        }
        queue_.push_back(Request{key, features, std::move(cb)});
    }
    submitted_.fetch_add(1, std::memory_order_relaxed);
    cv_.notify_one();
    return true;
}

void AIDecisionEngine::workerLoop(std::stop_token st) {
    std::vector<Request> batch;
    std::vector<FeatureVector> rows;
    batch.reserve(cfg_.maxBatch);
    rows.reserve(cfg_.maxBatch);
    while (!st.stop_requested()) {
        std::shared_ptr<IModel> model;
        {
            std::unique_lock lock(mutex_);
            if (!cv_.wait(lock, st, [this] { return !queue_.empty(); })) return;  // stop forespurt
            while (!queue_.empty() && batch.size() < cfg_.maxBatch) {
                batch.push_back(std::move(queue_.front()));
                queue_.pop_front();
            }
            model = model_;  // ta kopi under lås; pågående batch bruker denne
        }
        if (!model) {
            batch.clear();
            continue;
        }

        rows.clear();
        for (const auto& r : batch) rows.push_back(r.features);

        std::vector<float> scores;
        std::string error;
        try {
            scores = model->predictBatch(rows);
            if (scores.size() != batch.size()) throw std::runtime_error("modellen returnerte feil antall resultater");
            recordSuccess();
        } catch (const std::exception& e) {
            error = e.what();
            recordFailure(error);
        } catch (...) {
            error = "ukjent unntak i modell";
            recordFailure(error);
        }

        for (std::size_t i = 0; i < batch.size(); ++i) {
            InferenceResult res;
            res.key = batch[i].key;
            if (error.empty()) {
                res.ok = true;
                res.score = scores[i];
                res.verdict = classify(scores[i]);
                if (res.verdict == Verdict::Block) blocks_.fetch_add(1, std::memory_order_relaxed);
            } else {
                res.error = error;
            }
            completed_.fetch_add(1, std::memory_order_relaxed);
            if (batch[i].cb) {
                try {
                    batch[i].cb(res);
                } catch (const std::exception& e) {
                    spdlog::error("inferens-callback kastet: {}", e.what());
                }
            }
        }
        batch.clear();
    }
}

void AIDecisionEngine::recordFailure(const std::string& what) {
    errors_.fetch_add(1, std::memory_order_relaxed);
    const auto n = consecutiveErrors_.fetch_add(1) + 1;
    spdlog::error("AI-inferens feilet ({} på rad): {}", n, what);
    if (n >= cfg_.maxConsecutiveErrors) {
        const auto until = nowNs() + std::chrono::duration_cast<std::chrono::nanoseconds>(cfg_.errorCooldown).count();
        breakerOpenUntilNs_.store(until, std::memory_order_release);
        spdlog::error("Circuit breaker åpen i {}s – kun regelmotor brukes", cfg_.errorCooldown.count());
    }
}

void AIDecisionEngine::recordSuccess() {
    if (consecutiveErrors_.exchange(0) >= cfg_.maxConsecutiveErrors) spdlog::info("AI-inferens fungerer igjen");
    breakerOpenUntilNs_.store(0, std::memory_order_release);
}

AiStats AIDecisionEngine::stats() const {
    AiStats s;
    s.submitted = submitted_.load();
    s.completed = completed_.load();
    s.rejectedQueueFull = rejected_.load();
    s.errors = errors_.load();
    s.blocks = blocks_.load();
    s.healthy = healthy();
    std::lock_guard lock(mutex_);
    s.queueDepth = queue_.size();
    return s;
}

std::string AIDecisionEngine::modelName() const {
    std::lock_guard lock(mutex_);
    return model_ ? model_->name() : "<none>";
}

}  // namespace aifw
