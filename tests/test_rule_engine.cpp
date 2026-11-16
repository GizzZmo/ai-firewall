#include <gtest/gtest.h>

#include <filesystem>

#include <nlohmann/json.hpp>

#include "RuleEngine.hpp"

using namespace aifw;
using nlohmann::json;

namespace {
MatchContext ctx(const std::string& remote, std::uint16_t rport, Protocol proto = Protocol::TCP,
                 Direction dir = Direction::Outbound, const std::string& app = {}, std::uint16_t lport = 50000) {
    MatchContext c;
    c.key.localIp = *IpAddress::parse("192.168.1.10");
    c.key.remoteIp = *IpAddress::parse(remote);
    c.key.localPort = lport;
    c.key.remotePort = rport;
    c.key.protocol = proto;
    c.direction = dir;
    c.appPath = app;
    return c;
}

const json kRules = json::parse(R"({
  "version": 1,
  "rules": [
    {"id": "allow-dns", "action": "allow", "direction": "out", "protocol": "udp", "remote_ports": [53], "priority": 100},
    {"id": "block-telnet", "action": "deny", "protocol": "tcp", "remote_ports": [23, "2323"], "priority": 90},
    {"id": "block-badnet", "action": "deny", "remote_ips": ["203.0.113.0/24", "2001:db8:bad::/48"], "priority": 80},
    {"id": "allow-lan", "action": "allow", "remote_ips": ["192.168.0.0/16", "fe80::/10"], "priority": 80},
    {"id": "allow-browser", "action": "allow", "direction": "out", "protocol": "tcp", "remote_ports": ["80", "443"], "app": "*\\chrome.exe", "priority": 50},
    {"id": "block-rdp-in", "action": "deny", "direction": "in", "protocol": "tcp", "local_ports": ["3389"], "priority": 70},
    {"id": "disabled", "action": "deny", "remote_ports": ["1-65535"], "enabled": false, "priority": 1000}
  ]
})");
}  // namespace

TEST(RuleEngine, LoadsAndMatchesByPort) {
    RuleEngine re;
    re.loadFromJson(kRules);
    EXPECT_EQ(re.size(), 7u);
    auto m = re.match(ctx("8.8.8.8", 53, Protocol::UDP));
    ASSERT_TRUE(m);
    EXPECT_EQ(m->ruleId, "allow-dns");
    EXPECT_EQ(m->verdict, Verdict::Allow);
    EXPECT_EQ(re.match(ctx("8.8.8.8", 2323))->ruleId, "block-telnet");
    EXPECT_FALSE(re.match(ctx("8.8.8.8", 53, Protocol::TCP)));  // dns-regelen er kun UDP
}

TEST(RuleEngine, CidrMatchingAndPriorityTieBreakDenyWins) {
    RuleEngine re;
    re.loadFromJson(kRules);
    auto m = re.match(ctx("203.0.113.55", 8080));
    ASSERT_TRUE(m);
    EXPECT_EQ(m->ruleId, "block-badnet");
    EXPECT_EQ(re.match(ctx("192.168.5.5", 8080))->ruleId, "allow-lan");
    EXPECT_EQ(re.match(ctx("2001:db8:bad:1::5", 443))->ruleId, "block-badnet");
    EXPECT_EQ(re.match(ctx("fe80::1", 443))->ruleId, "allow-lan");
}

TEST(RuleEngine, AppMatchingIsCaseInsensitiveAndSupportsWildcards) {
    RuleEngine re;
    re.loadFromJson(kRules);
    auto m = re.match(ctx("142.250.74.110", 443, Protocol::TCP, Direction::Outbound,
                          "C:\\Program Files\\Google\\Chrome\\Application\\CHROME.EXE"));
    ASSERT_TRUE(m);
    EXPECT_EQ(m->ruleId, "allow-browser");
    EXPECT_FALSE(re.match(ctx("142.250.74.110", 443, Protocol::TCP, Direction::Outbound, "C:\\evil\\chrome.exe.bat")));
    EXPECT_FALSE(re.match(ctx("142.250.74.110", 443)));  // ukjent app matcher ikke app-regel
}

TEST(RuleEngine, DirectionAndLocalPort) {
    RuleEngine re;
    re.loadFromJson(kRules);
    EXPECT_EQ(re.match(ctx("8.8.4.4", 51515, Protocol::TCP, Direction::Inbound, {}, 3389))->ruleId, "block-rdp-in");
    EXPECT_FALSE(re.match(ctx("8.8.4.4", 51515, Protocol::TCP, Direction::Outbound, {}, 3389)));
}

TEST(RuleEngine, WildcardMatch) {
    EXPECT_TRUE(RuleEngine::wildcardMatch("*.exe", "a.EXE"));
    EXPECT_TRUE(RuleEngine::wildcardMatch("c:\\program files\\*\\app?.exe", "C:\\Program Files\\X\\Y\\app1.exe"));
    EXPECT_FALSE(RuleEngine::wildcardMatch("app?.exe", "app.exe"));
    EXPECT_TRUE(RuleEngine::wildcardMatch("*", ""));
    EXPECT_FALSE(RuleEngine::wildcardMatch("", "x"));
    EXPECT_TRUE(RuleEngine::appMatches("firefox.exe", "C:/Program Files/Mozilla Firefox/firefox.exe"));
}

TEST(RuleEngine, RejectsInvalidRulesAtomically) {
    RuleEngine re;
    re.loadFromJson(kRules);
    auto bad = json::parse(R"({"rules":[{"id":"x","action":"allow"},{"id":"y","action":"explode"}]})");
    EXPECT_THROW(re.loadFromJson(bad), std::runtime_error);
    EXPECT_EQ(re.size(), 7u);  // uendret
    EXPECT_THROW(re.loadFromJson(json::parse(R"({"rules":[{"id":"a","action":"allow","remote_ips":["1.2.3.999"]}]})")),
                 std::runtime_error);
    EXPECT_THROW(re.loadFromJson(json::parse(R"({"rules":[{"id":"a","action":"allow","remote_ports":["90-80"]}]})")),
                 std::runtime_error);
    EXPECT_THROW(re.loadFromJson(json::parse(R"({"rules":[{"id":"a","action":"allow"},{"id":"a","action":"deny"}]})")),
                 std::runtime_error);
    EXPECT_THROW(re.loadFromJson(json::parse(R"({"nope":[]})")), std::runtime_error);
}

TEST(RuleEngine, AddRemoveAndRoundTripJson) {
    RuleEngine re;
    re.loadFromJson(kRules);
    Rule r;
    r.id = "block-all-high";
    r.action = Verdict::Block;
    r.remotePorts = {{40000, 41000}};
    r.priority = 5;
    re.addRule(r);
    EXPECT_EQ(re.match(ctx("8.8.8.8", 40500))->ruleId, "block-all-high");
    EXPECT_TRUE(re.removeRule("block-all-high"));
    EXPECT_FALSE(re.removeRule("block-all-high"));

    RuleEngine copy;
    copy.loadFromJson(re.toJson());
    EXPECT_EQ(copy.size(), re.size());
    EXPECT_EQ(copy.match(ctx("203.0.113.1", 1))->ruleId, "block-badnet");
    EXPECT_EQ(copy.match(ctx("142.250.74.110", 443, Protocol::TCP, Direction::Outbound, "c:\\x\\chrome.exe"))->ruleId,
              "allow-browser");

    const auto path = std::filesystem::temp_directory_path() / "aifw_rules_roundtrip.json";
    re.saveToFile(path);
    RuleEngine fromFile;
    fromFile.loadFromFile(path);
    EXPECT_EQ(fromFile.size(), re.size());
    std::filesystem::remove(path);
}

TEST(RuleEngine, ShippedExampleRulesAreValid) {
    RuleEngine re;
    ASSERT_NO_THROW(re.loadFromFile(std::string(AIFW_SOURCE_DIR) + "/config/rules.json"));
    EXPECT_GT(re.size(), 0u);
}
