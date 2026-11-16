#include <gtest/gtest.h>

#include <fstream>

#include <nlohmann/json.hpp>

#include "FeatureExtractor.hpp"
#include "FlowTracker.hpp"
#include "TestPackets.hpp"

using namespace aifw;
using namespace aifw::test;

TEST(FeatureExtractor, ParsesIpv4Tcp) {
    std::vector<std::uint8_t> payload{'h', 'e', 'l', 'l', 'o'};
    auto p = ipv4("192.168.1.10", "93.184.216.34", Protocol::TCP, 50123, 443, tcpflags::SYN | tcpflags::ACK, payload);
    auto info = FeatureExtractor::parse(p, Direction::Outbound);
    ASSERT_TRUE(info);
    EXPECT_EQ(info->protocol, Protocol::TCP);
    EXPECT_EQ(info->srcIp.toString(), "192.168.1.10");
    EXPECT_EQ(info->dstIp.toString(), "93.184.216.34");
    EXPECT_EQ(info->srcPort, 50123);
    EXPECT_EQ(info->dstPort, 443);
    EXPECT_EQ(info->tcpFlags, tcpflags::SYN | tcpflags::ACK);
    EXPECT_EQ(info->ttl, 64);
    EXPECT_EQ(info->totalLength, p.size());
    ASSERT_EQ(info->payloadLength, 5u);
    EXPECT_EQ(info->payload[0], 'h');
}

TEST(FeatureExtractor, ParsesIpv4Udp) {
    auto p = ipv4("10.0.0.2", "8.8.8.8", Protocol::UDP, 5353, 53, 0, {1, 2, 3});
    auto info = FeatureExtractor::parse(p, Direction::Outbound);
    ASSERT_TRUE(info);
    EXPECT_EQ(info->protocol, Protocol::UDP);
    EXPECT_EQ(info->dstPort, 53);
    EXPECT_EQ(info->payloadLength, 3u);
}

TEST(FeatureExtractor, ParsesIpv6TcpWithExtensionHeader) {
    auto p = ipv6("2001:db8::10", "2001:db8::1", Protocol::TCP, 40000, 22, tcpflags::SYN, {9, 9}, true);
    auto info = FeatureExtractor::parse(p, Direction::Outbound);
    ASSERT_TRUE(info);
    EXPECT_EQ(info->srcIp.version, 6);
    EXPECT_EQ(info->protocol, Protocol::TCP);
    EXPECT_EQ(info->dstPort, 22);
    EXPECT_EQ(info->payloadLength, 2u);
}

TEST(FeatureExtractor, ParsesIcmpTypeCode) {
    auto p = ipv4("10.0.0.2", "10.0.0.1", Protocol::ICMP, 8, 0);
    auto info = FeatureExtractor::parse(p, Direction::Outbound);
    ASSERT_TRUE(info);
    EXPECT_EQ(info->protocol, Protocol::ICMP);
    EXPECT_EQ(info->srcPort, 8);  // echo request
}

TEST(FeatureExtractor, RejectsTruncatedAndGarbage) {
    auto p = ipv4("10.0.0.2", "10.0.0.1", Protocol::TCP, 1, 2);
    for (std::size_t len : {0u, 1u, 19u, 20u, 39u}) {
        std::vector<std::uint8_t> cut(p.begin(), p.begin() + static_cast<long>(len));
        EXPECT_FALSE(FeatureExtractor::parse(cut, Direction::Outbound)) << len;
    }
    std::vector<std::uint8_t> garbage(60, 0xFF);
    EXPECT_FALSE(FeatureExtractor::parse(garbage, Direction::Outbound));
    // IHL < 5
    auto bad = p;
    bad[0] = 0x44;
    EXPECT_FALSE(FeatureExtractor::parse(bad, Direction::Outbound));
    // Total length større enn buffer
    auto big = p;
    put16(big, 2, 1500);
    EXPECT_FALSE(FeatureExtractor::parse(big, Direction::Outbound));
    // TCP data offset < 5
    auto off = p;
    off[20 + 12] = 0x40;
    EXPECT_FALSE(FeatureExtractor::parse(off, Direction::Outbound));
}

TEST(FeatureExtractor, NonFirstFragmentHasNoPorts) {
    auto p = ipv4("10.0.0.2", "10.0.0.1", Protocol::UDP, 1000, 2000, 0, {1, 2, 3, 4});
    put16(p, 6, 0x0010);  // fragment offset 16*8
    auto info = FeatureExtractor::parse(p, Direction::Outbound);
    ASSERT_TRUE(info);
    EXPECT_EQ(info->srcPort, 0);
    EXPECT_EQ(info->dstPort, 0);
}

TEST(FeatureExtractor, ExtractsFlowFeatures) {
    FlowTracker ft;
    auto t0 = Clock::now();
    std::vector<std::uint8_t> payload(200);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::uint8_t>(i * 37);
    auto out = ipv4("192.168.1.10", "1.2.3.4", Protocol::TCP, 50000, 8443, tcpflags::SYN, payload);
    auto in = ipv4("1.2.3.4", "192.168.1.10", Protocol::TCP, 8443, 50000, tcpflags::ACK);
    auto po = *FeatureExtractor::parse(out, Direction::Outbound);
    auto pi = *FeatureExtractor::parse(in, Direction::Inbound);
    ft.update(po, t0);
    ft.update(pi, t0 + std::chrono::milliseconds(100));
    auto s = ft.update(po, t0 + std::chrono::milliseconds(300));
    ASSERT_TRUE(s);
    auto f = FeatureExtractor::extract(po.flowKey(), *s);
    auto at = [&](Feature x) { return f[static_cast<std::size_t>(x)]; };
    EXPECT_NEAR(at(Feature::DurationSec), 0.3, 1e-6);
    EXPECT_EQ(at(Feature::FwdPackets), 2);
    EXPECT_EQ(at(Feature::BwdPackets), 1);
    EXPECT_EQ(at(Feature::FwdBytes), 2.0f * static_cast<float>(out.size()));
    EXPECT_EQ(at(Feature::SynCount), 2);
    EXPECT_NEAR(at(Feature::IatMeanMs), 150.0, 1e-3);
    EXPECT_NEAR(at(Feature::DstPortNorm), 8443.0 / 65535.0, 1e-6);
    EXPECT_EQ(at(Feature::ProtocolTcp), 1.0f);
    EXPECT_EQ(at(Feature::ProtocolUdp), 0.0f);
    EXPECT_GT(at(Feature::PayloadEntropyMean), 5.0f);
    EXPECT_NEAR(at(Feature::PacketsPerSec), 10.0, 1e-3);
    EXPECT_NEAR(at(Feature::FwdBwdRatio), 1.0, 1e-6);
    for (float v : f) EXPECT_TRUE(std::isfinite(v));
}

// Sikrer at C++-skjemaet og Python-pipelinen (ml/feature_schema.json) er i synk.
TEST(FeatureSchema, MatchesPythonSchema) {
    std::ifstream in(std::string(AIFW_SOURCE_DIR) + "/ml/feature_schema.json");
    ASSERT_TRUE(in) << "fant ikke ml/feature_schema.json";
    auto j = nlohmann::json::parse(in);
    EXPECT_EQ(j.at("version").get<std::size_t>(), kFeatureSchemaVersion);
    const auto& names = j.at("features");
    ASSERT_EQ(names.size(), kFeatureCount);
    for (std::size_t i = 0; i < kFeatureCount; ++i) EXPECT_EQ(names[i].get<std::string>(), kFeatureNames[i]) << i;
}
