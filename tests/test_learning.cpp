#include <gtest/gtest.h>

#include <filesystem>

#include <nlohmann/json.hpp>

#include "LearningMode.hpp"

using namespace aifw;

namespace {
MatchContext ctx(std::uint16_t port, const std::string& app, const std::string& ip = "1.2.3.4") {
    MatchContext c;
    c.key.localIp = *IpAddress::parse("192.168.1.10");
    c.key.remoteIp = *IpAddress::parse(ip);
    c.key.localPort = 50000;
    c.key.remotePort = port;
    c.key.protocol = Protocol::TCP;
    c.direction = Direction::Outbound;
    c.appPath = app;
    return c;
}
}  // namespace

TEST(LearningMode, SuggestsAllowForFrequentBenignAndDenyForAiFlagged) {
    LearningMode lm(true);
    for (int i = 0; i < 5; ++i) lm.recordFlow(ctx(443, "C:\\Apps\\chrome.exe", "1.2.3." + std::to_string(i)));
    lm.recordFlow(ctx(8080, "C:\\Apps\\rare.exe"));  // for sjelden
    for (int i = 0; i < 4; ++i) {
        lm.recordFlow(ctx(4444, "C:\\Temp\\x.exe"));
        lm.recordAiVerdict(ctx(4444, "C:\\Temp\\x.exe"), 0.97f);
    }
    auto rules = lm.suggestRules(3, 3);
    ASSERT_EQ(rules.size(), 2u);
    const Rule* allow = nullptr;
    const Rule* deny = nullptr;
    for (const auto& r : rules) (r.action == Verdict::Allow ? allow : deny) = &r;
    ASSERT_TRUE(allow && deny);
    EXPECT_EQ(allow->app, "C:\\Apps\\chrome.exe");
    EXPECT_EQ(allow->remotePorts.front().first, 443);
    EXPECT_EQ(allow->source, "learning");
    EXPECT_EQ(deny->app, "C:\\Temp\\x.exe");
    EXPECT_GT(deny->priority, allow->priority);
    EXPECT_EQ(lm.snapshot().at({"C:\\Apps\\chrome.exe", Direction::Outbound, Protocol::TCP, 443}).remoteIps.size(), 5u);
}

TEST(LearningMode, SuggestedRulesAreLoadableByRuleEngine) {
    LearningMode lm(true);
    for (int i = 0; i < 3; ++i) lm.recordFlow(ctx(443, "C:\\Program Files\\App (x86)\\a b.exe"));
    RuleEngine re;
    for (auto& r : lm.suggestRules()) re.addRule(r);
    RuleEngine reload;
    ASSERT_NO_THROW(reload.loadFromJson(re.toJson()));
    EXPECT_EQ(reload.size(), 1u);
    auto m = reload.match(ctx(443, "C:\\Program Files\\App (x86)\\a b.exe"));
    ASSERT_TRUE(m);
    EXPECT_EQ(m->verdict, Verdict::Allow);
}

TEST(LearningMode, PersistsToDisk) {
    LearningMode lm(true);
    lm.recordFlow(ctx(53, "dns.exe"));
    lm.recordAiVerdict(ctx(53, "dns.exe"), 0.5f);
    const auto path = std::filesystem::temp_directory_path() / "aifw_learning_test" / "learning.json";
    lm.save(path);
    LearningMode loaded;
    loaded.load(path);
    auto snap = loaded.snapshot();
    ASSERT_EQ(snap.size(), 1u);
    EXPECT_EQ(snap.begin()->second.flows, 1u);
    EXPECT_EQ(snap.begin()->second.aiFlagged, 1u);
    std::filesystem::remove_all(path.parent_path());
}
