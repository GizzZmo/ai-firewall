#include <gtest/gtest.h>

#include <thread>

#include <nlohmann/json.hpp>

#include "DecisionCoordinator.hpp"
#include "FeatureExtractor.hpp"
#include "TestPackets.hpp"

using namespace aifw;
using namespace aifw::test;
using namespace std::chrono_literals;

namespace {

/// Modell som gir fast score og teller kall.
class FixedModel : public IModel {
public:
    explicit FixedModel(float s) : score(s) {}
    std::atomic<float> score;
    std::atomic<bool> fail{false};
    std::atomic<int> calls{0};
    std::vector<float> predictBatch(std::span<const FeatureVector> rows) override {
        ++calls;
        if (fail) throw std::runtime_error("boom");
        return std::vector<float>(rows.size(), score.load());
    }
    std::string name() const override { return "fixed"; }
};

class RecordingSink : public IPersistentRuleSink {
public:
    std::atomic<int> count{0};
    void persistBlock(const FlowKey&, const std::string&, const std::string&) override { ++count; }
};

struct Harness {
    Config cfg;
    RuleEngine rules;
    FlowTracker flows;
    VerdictCache cache{1000};
    LearningMode learning;
    MemoryNotifier notifier;
    RecordingSink sink;
    FixedModel* model{nullptr};
    std::unique_ptr<AIDecisionEngine> ai;
    std::unique_ptr<DecisionCoordinator> dc;
    std::vector<std::uint8_t> buf;

    explicit Harness(float score, bool learningMode = false) {
        cfg.ai.minPacketsBeforeInference = 2;
        cfg.ai.reevaluateEveryPackets = 1000;
        cfg.ai.workerThreads = 1;
        cfg.ai.maxConsecutiveErrors = 1;
        cfg.ai.errorCooldown = 60s;
        cfg.wfp.persistAiBlocks = true;
        learning.setEnabled(learningMode);
        auto m = std::make_unique<FixedModel>(score);
        model = m.get();
        ai = std::make_unique<AIDecisionEngine>(std::move(m), cfg.ai);
        dc = std::make_unique<DecisionCoordinator>(cfg, rules, flows, cache, ai.get(), learning, notifier, &sink);
    }
    ~Harness() {
        ai->stop();
        dc.reset();
    }
    PacketInfo out(std::uint16_t dport, std::uint16_t sport = 50000) {
        buf = ipv4("192.168.1.10", "198.51.100.7", Protocol::TCP, sport, dport, tcpflags::ACK);
        return *FeatureExtractor::parse(buf, Direction::Outbound);
    }
    void waitAiIdle() {
        for (int i = 0; i < 200; ++i) {
            auto s = ai->stats();
            if (s.completed >= s.submitted && s.queueDepth == 0) {
                std::this_thread::sleep_for(5ms);
                return;
            }
            std::this_thread::sleep_for(5ms);
        }
    }
};

}  // namespace

TEST(DecisionCoordinator, RuleWinsImmediately) {
    Harness h(0.99f);
    h.rules.loadFromJson(nlohmann::json::parse(R"({"rules":[{"id":"no-telnet","action":"deny","remote_ports":[23]}]})"));
    auto d = h.dc->decide(h.out(23));
    EXPECT_EQ(d.verdict, Verdict::Block);
    EXPECT_EQ(d.source, DecisionSource::Rule);
    EXPECT_EQ(d.ruleId, "no-telnet");
    EXPECT_EQ(h.model->calls.load(), 0);
}

TEST(DecisionCoordinator, AiBlockIsAsyncThenCached) {
    Harness h(0.99f);
    auto d1 = h.dc->decide(h.out(4444));
    EXPECT_EQ(d1.verdict, Verdict::Allow);  // første pakke: for få pakker
    EXPECT_EQ(d1.source, DecisionSource::Default);
    auto d2 = h.dc->decide(h.out(4444));
    EXPECT_EQ(d2.verdict, Verdict::Allow);  // AI startet, men pakken venter ikke
    EXPECT_EQ(d2.source, DecisionSource::AiPending);
    h.waitAiIdle();
    auto d3 = h.dc->decide(h.out(4444));
    EXPECT_EQ(d3.verdict, Verdict::Block);
    EXPECT_EQ(d3.source, DecisionSource::Cache);
    ASSERT_FALSE(h.notifier.events().empty());
    EXPECT_EQ(h.notifier.events().back().type, EventType::Blocked);
    EXPECT_EQ(h.sink.count.load(), 1);
    // Annen flyt påvirkes ikke.
    EXPECT_EQ(h.dc->decide(h.out(4444, 50001)).verdict, Verdict::Allow);
}

TEST(DecisionCoordinator, LearningModeNeverBlocksOnAi) {
    Harness h(0.99f, /*learning=*/true);
    h.dc->decide(h.out(4444));
    h.dc->decide(h.out(4444));
    h.waitAiIdle();
    auto d = h.dc->decide(h.out(4444));
    EXPECT_EQ(d.verdict, Verdict::Allow);
    EXPECT_EQ(d.source, DecisionSource::Learning);
    EXPECT_EQ(h.notifier.events().back().type, EventType::WouldBlock);
    EXPECT_EQ(h.sink.count.load(), 0);
    EXPECT_EQ(h.dc->stats().wouldBlock, 1u);
    EXPECT_FALSE(h.learning.snapshot().empty());
}

TEST(DecisionCoordinator, FailSafeWhenModelFails) {
    Harness h(0.99f);
    h.model->fail = true;
    h.dc->decide(h.out(4444));
    h.dc->decide(h.out(4444));
    h.waitAiIdle();
    // Breaker åpen etter én feil (maxConsecutiveErrors=1): regel/standard brukes.
    auto d = h.dc->decide(h.out(4444));
    EXPECT_EQ(d.verdict, h.cfg.defaultVerdict);
    EXPECT_EQ(d.source, DecisionSource::FailSafe);
    EXPECT_FALSE(h.ai->healthy());
    bool sawAiError = false;
    for (auto& e : h.notifier.events()) sawAiError |= e.type == EventType::AiError;
    EXPECT_TRUE(sawAiError);
}

TEST(DecisionCoordinator, LowScoreCachedAsAllow) {
    Harness h(0.01f);
    h.dc->decide(h.out(443));
    h.dc->decide(h.out(443));
    h.waitAiIdle();
    auto d = h.dc->decide(h.out(443));
    EXPECT_EQ(d.verdict, Verdict::Allow);
    EXPECT_EQ(d.source, DecisionSource::Cache);
    EXPECT_EQ(h.dc->stats().blocked, 0u);
}

TEST(DecisionCoordinator, CachedAllowIsReevaluatedAndCanTurnIntoBlock) {
    Harness h(0.01f);
    h.cfg.ai.reevaluateEveryPackets = 3;  // cfg leses ved hvert kall
    h.dc->decide(h.out(8080));
    h.dc->decide(h.out(8080));  // inferens #1 (score lav)
    h.waitAiIdle();
    EXPECT_EQ(h.dc->decide(h.out(8080)).source, DecisionSource::Cache);
    h.model->score = 0.99f;    // flyten "endrer karakter"
    h.dc->decide(h.out(8080));
    h.dc->decide(h.out(8080));  // pakke 5 = 2 + 3 -> ny inferens, fortsatt Allow fra cache
    h.waitAiIdle();
    auto d = h.dc->decide(h.out(8080));
    EXPECT_EQ(d.verdict, Verdict::Block);
    EXPECT_EQ(d.source, DecisionSource::Cache);
}
