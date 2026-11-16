// Sammenligner C++-features med Python (ml/aifw_ml/features.py) for identiske pakkesekvenser.
// Fixture: tests/data/feature_parity.json (lages med `python -m aifw_ml.export_parity_fixture`).
#include <gtest/gtest.h>

#include <cmath>
#include <fstream>

#include <nlohmann/json.hpp>

#include "FeatureExtractor.hpp"
#include "FlowTracker.hpp"
#include "TestPackets.hpp"

using namespace aifw;
using namespace aifw::test;

namespace {
std::vector<std::uint8_t> fromHex(const std::string& h) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(static_cast<std::uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
    return out;
}
}  // namespace

TEST(FeatureParity, PythonAndCppAgree) {
    std::ifstream in(std::string(AIFW_SOURCE_DIR) + "/tests/data/feature_parity.json");
    ASSERT_TRUE(in) << "mangler tests/data/feature_parity.json";
    const auto j = nlohmann::json::parse(in);
    ASSERT_EQ(j["features"].size(), kFeatureCount);
    for (std::size_t i = 0; i < kFeatureCount; ++i) ASSERT_EQ(j["features"][i].get<std::string>(), kFeatureNames[i]);

    for (const auto& flow : j["flows"]) {
        FlowTracker ft;
        const auto proto = static_cast<Protocol>(flow["protocol"].get<int>());
        const auto rport = flow["remote_port"].get<std::uint16_t>();
        const auto lport = flow["local_port"].get<std::uint16_t>();
        const auto t0 = Clock::now();
        std::optional<FlowStats> stats;
        FlowKey key;
        for (const auto& p : flow["packets"]) {
            const bool out = p["outbound"].get<bool>();
            const auto flags = p["flags"].get<std::uint8_t>();
            const auto payload = fromHex(p["payload_hex"].get<std::string>());
            auto buf = out ? ipv4("192.168.1.10", "203.0.113.9", proto, lport, rport, flags, payload)
                           : ipv4("203.0.113.9", "192.168.1.10", proto, rport, lport, flags, payload);
            auto info = FeatureExtractor::parse(buf, out ? Direction::Outbound : Direction::Inbound);
            ASSERT_TRUE(info);
            key = info->flowKey();
            stats = ft.update(*info, t0 + std::chrono::microseconds(p["t_us"].get<std::int64_t>()));
        }
        ASSERT_TRUE(stats);
        const auto f = FeatureExtractor::extract(key, *stats);
        for (std::size_t i = 0; i < kFeatureCount; ++i) {
            const double expected = flow["expected"][std::string(kFeatureNames[i])].get<double>();
            const double tol = 1e-4 * std::max(1.0, std::abs(expected));
            EXPECT_NEAR(f[i], expected, tol) << "feature " << kFeatureNames[i] << " i flyt port " << rport;
        }
    }
}
