#include <gtest/gtest.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#include "AIDecisionEngine.hpp"

using namespace aifw;
using namespace std::chrono_literals;

namespace {

/// Testmodell: score = første feature. Kan settes til å feile eller være treg.
class FakeModel : public IModel {
public:
    std::atomic<bool> fail{false};
    std::atomic<int> delayMs{0};
    std::atomic<int> calls{0};
    std::vector<float> predictBatch(std::span<const FeatureVector> rows) override {
        ++calls;
        if (delayMs) std::this_thread::sleep_for(std::chrono::milliseconds(delayMs.load()));
        if (fail) throw std::runtime_error("simulert modellfeil");
        std::vector<float> out;
        for (const auto& r : rows) out.push_back(r[0]);
        return out;
    }
    std::string name() const override { return "fake"; }
};

struct Waiter {
    std::mutex m;
    std::condition_variable cv;
    std::vector<InferenceResult> results;
    void push(const InferenceResult& r) {
        std::lock_guard l(m);
        results.push_back(r);
        cv.notify_all();
    }
    bool waitFor(std::size_t n, std::chrono::milliseconds t = 2s) {
        std::unique_lock l(m);
        return cv.wait_for(l, t, [&] { return results.size() >= n; });
    }
};

FeatureVector fv(float first) {
    FeatureVector f{};
    f[0] = first;
    return f;
}

AiConfig cfg() {
    AiConfig c;
    c.workerThreads = 2;
    c.queueCapacity = 16;
    c.blockThreshold = 0.9;
    c.allowThreshold = 0.3;
    c.maxConsecutiveErrors = 2;
    c.errorCooldown = 1s;
    return c;
}

}  // namespace

TEST(AIDecisionEngine, ClassifiesAsynchronouslyWithThresholds) {
    auto model = std::make_unique<FakeModel>();
    AIDecisionEngine ai(std::move(model), cfg());
    Waiter w;
    FlowKey k;
    ASSERT_TRUE(ai.submit(k, fv(0.95f), [&](const InferenceResult& r) { w.push(r); }));
    ASSERT_TRUE(ai.submit(k, fv(0.10f), [&](const InferenceResult& r) { w.push(r); }));
    ASSERT_TRUE(ai.submit(k, fv(0.50f), [&](const InferenceResult& r) { w.push(r); }));
    ASSERT_TRUE(w.waitFor(3));
    int block = 0, allow = 0, unknown = 0;
    for (auto& r : w.results) {
        EXPECT_TRUE(r.ok);
        if (r.verdict == Verdict::Block) ++block;
        if (r.verdict == Verdict::Allow) ++allow;
        if (r.verdict == Verdict::Unknown) ++unknown;
    }
    EXPECT_EQ(block, 1);
    EXPECT_EQ(allow, 1);
    EXPECT_EQ(unknown, 1);
}

TEST(AIDecisionEngine, RejectsWhenQueueFullInsteadOfBlocking) {
    auto model = std::make_unique<FakeModel>();
    model->delayMs = 200;
    auto c = cfg();
    c.workerThreads = 1;
    c.queueCapacity = 2;
    c.maxBatch = 1;
    AIDecisionEngine ai(std::move(model), c);
    FlowKey k;
    int accepted = 0;
    const auto start = Clock::now();
    for (int i = 0; i < 20; ++i) accepted += ai.submit(k, fv(0.1f), {}) ? 1 : 0;
    EXPECT_LT(Clock::now() - start, 100ms);  // submit blokkerer aldri
    EXPECT_LE(accepted, 3);
    EXPECT_GE(ai.stats().rejectedQueueFull, 17u);
}

TEST(AIDecisionEngine, ErrorsReportedAndCircuitBreakerOpens) {
    auto model = std::make_unique<FakeModel>();
    auto* raw = model.get();
    raw->fail = true;
    auto c = cfg();
    c.workerThreads = 1;
    c.maxBatch = 1;
    AIDecisionEngine ai(std::move(model), c);
    Waiter w;
    FlowKey k;
    ai.submit(k, fv(0.99f), [&](const InferenceResult& r) { w.push(r); });
    ASSERT_TRUE(w.waitFor(1));
    ai.submit(k, fv(0.99f), [&](const InferenceResult& r) { w.push(r); });
    ASSERT_TRUE(w.waitFor(2));
    for (auto& r : w.results) {
        EXPECT_FALSE(r.ok);
        EXPECT_FALSE(r.error.empty());
    }
    EXPECT_FALSE(ai.healthy());
    EXPECT_FALSE(ai.submit(k, fv(0.99f), {}));  // breaker åpen

    // Etter cooldown: half-open, ny vellykket kjøring lukker breakeren.
    std::this_thread::sleep_for(1100ms);
    raw->fail = false;
    EXPECT_TRUE(ai.healthy());
    ASSERT_TRUE(ai.submit(k, fv(0.1f), [&](const InferenceResult& r) { w.push(r); }));
    ASSERT_TRUE(w.waitFor(3));
    EXPECT_TRUE(w.results.back().ok);
    EXPECT_TRUE(ai.healthy());
}

TEST(AIDecisionEngine, StopDrainsPendingWithNotOk) {
    auto model = std::make_unique<FakeModel>();
    model->delayMs = 100;
    auto c = cfg();
    c.workerThreads = 1;
    c.maxBatch = 1;
    std::atomic<int> notOk{0}, total{0};
    {
        AIDecisionEngine ai(std::move(model), c);
        FlowKey k;
        for (int i = 0; i < 5; ++i)
            ai.submit(k, fv(0.1f), [&](const InferenceResult& r) {
                ++total;
                if (!r.ok) ++notOk;
            });
        std::this_thread::sleep_for(20ms);
    }  // destruktør stopper
    EXPECT_EQ(total.load(), 5);  // alle fikk svar
    EXPECT_GE(notOk.load(), 1);
}

TEST(HeuristicModel, FlagsSynScanButNotNormalFlow) {
    FeatureVector scan{};
    scan[static_cast<std::size_t>(Feature::SynCount)] = 20;
    scan[static_cast<std::size_t>(Feature::BwdPackets)] = 0;
    scan[static_cast<std::size_t>(Feature::FwdPackets)] = 20;
    scan[static_cast<std::size_t>(Feature::PacketsPerSec)] = 5000;
    scan[static_cast<std::size_t>(Feature::FwdBwdRatio)] = 20;
    scan[static_cast<std::size_t>(Feature::RstCount)] = 0;
    FeatureVector normal{};
    normal[static_cast<std::size_t>(Feature::SynCount)] = 1;
    normal[static_cast<std::size_t>(Feature::FwdPackets)] = 10;
    normal[static_cast<std::size_t>(Feature::BwdPackets)] = 12;
    EXPECT_GT(HeuristicModel::score(scan), HeuristicModel::score(normal));
    EXPECT_LT(HeuristicModel::score(normal), 0.3f);
}
