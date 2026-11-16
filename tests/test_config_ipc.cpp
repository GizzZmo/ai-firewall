#include <gtest/gtest.h>

#include <filesystem>

#include <nlohmann/json.hpp>

#include "Config.hpp"
#include "FirewallCore.hpp"
#include "IpcProtocol.hpp"

using namespace aifw;
using nlohmann::json;

TEST(Config, DefaultsAreValid) { EXPECT_NO_THROW(Config{}.validate()); }

TEST(Config, ParsesShippedExample) {
    auto c = Config::loadFromFile(std::string(AIFW_SOURCE_DIR) + "/config/config.json");
    EXPECT_GT(c.ai.blockThreshold, c.ai.allowThreshold);
    EXPECT_FALSE(c.windivert.filter.empty());
}

TEST(Config, RoundTripAndValidation) {
    Config c;
    c.ai.blockThreshold = 0.8;
    c.learningMode = true;
    c.flow.udpIdleTimeout = std::chrono::milliseconds(1234);
    auto c2 = Config::fromJson(c.toJson());
    EXPECT_DOUBLE_EQ(c2.ai.blockThreshold, 0.8);
    EXPECT_TRUE(c2.learningMode);
    EXPECT_EQ(c2.flow.udpIdleTimeout.count(), 1234);
    EXPECT_THROW(Config::fromJson(json::parse(R"({"ai":{"block_threshold":0.2,"allow_threshold":0.5}})")), std::runtime_error);
    EXPECT_THROW(Config::fromJson(json::parse(R"({"windivert":{"batch_size":0}})")), std::runtime_error);
    EXPECT_THROW(Config::fromJson(json::parse(R"({"default_verdict":"maybe"})")), std::runtime_error);
    EXPECT_THROW(Config::fromJson(json::parse(R"({"pipe_name":"a\\b"})")), std::runtime_error);
}

TEST(Ipc, DecoderHandlesSplitAndMultipleMessages) {
    ipc::LineDecoder d;
    auto a = d.feed(R"({"cmd":"pi)");
    EXPECT_TRUE(a.empty());
    auto b = d.feed("ng\"}\r\n{\"cmd\":\"get_status\"}\n{\"cmd\":");
    ASSERT_EQ(b.size(), 2u);
    EXPECT_EQ(b[0]["cmd"], "ping");
    EXPECT_EQ(b[1]["cmd"], "get_status");
    auto c = d.feed("\"x\"}\n");
    ASSERT_EQ(c.size(), 1u);
}

TEST(Ipc, DecoderRejectsGarbageAndOversized) {
    ipc::LineDecoder d;
    EXPECT_TRUE(d.feed("not json\n[1,2]\n").empty());
    EXPECT_EQ(d.rejected(), 2u);
    std::string huge(ipc::kMaxMessageBytes + 10, 'a');
    EXPECT_TRUE(d.feed(huge).empty());
    auto ok = d.feed("still-part-of-huge\n{\"cmd\":\"ping\"}\n");
    ASSERT_EQ(ok.size(), 1u);
    EXPECT_EQ(d.rejected(), 3u);
}

TEST(Ipc, EncodeIsSingleLine) {
    auto s = ipc::encode(json{{"msg", "a\nb"}});
    EXPECT_EQ(s.back(), '\n');
    EXPECT_EQ(std::count(s.begin(), s.end(), '\n'), 1);
}

class FirewallCoreTest : public ::testing::Test {
protected:
    std::filesystem::path dir = std::filesystem::temp_directory_path() / "aifw_core_test";
    void SetUp() override {
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir / "config");
        std::filesystem::copy_file(std::string(AIFW_SOURCE_DIR) + "/config/rules.json", dir / "config" / "rules.json");
    }
    void TearDown() override { std::filesystem::remove_all(dir); }
};

TEST_F(FirewallCoreTest, HandlesCommandsAndEnforcesAdmin) {
    Config cfg;
    cfg.logFile.clear();
    FirewallCore core(cfg, dir, std::make_unique<HeuristicModel>());
    auto st = core.handleCommand(json{{"cmd", "get_status"}}, false);
    EXPECT_TRUE(st["ok"].get<bool>());
    EXPECT_EQ(st["status"]["learning_mode"], false);
    EXPECT_EQ(st["status"]["ai"]["model"], "heuristic");

    auto denied = core.handleCommand(json{{"cmd", "set_learning"}, {"enabled", true}}, false);
    EXPECT_FALSE(denied["ok"].get<bool>());
    auto allowed = core.handleCommand(json{{"cmd", "set_learning"}, {"enabled", true}}, true);
    EXPECT_TRUE(allowed["ok"].get<bool>());
    EXPECT_TRUE(core.learning().enabled());

    EXPECT_FALSE(core.handleCommand(json{{"cmd", "nope"}}, true)["ok"].get<bool>());
    EXPECT_FALSE(core.handleCommand(json{{"x", 1}}, true)["ok"].get<bool>());
    EXPECT_TRUE(core.handleCommand(json{{"cmd", "reload_rules"}}, true)["ok"].get<bool>());
    EXPECT_TRUE(core.handleCommand(json{{"cmd", "get_suggestions"}}, false)["ok"].get<bool>());
    EXPECT_TRUE(core.handleCommand(json{{"cmd", "apply_suggestions"}}, true)["ok"].get<bool>());
}
