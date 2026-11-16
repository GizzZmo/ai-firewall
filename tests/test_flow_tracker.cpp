#include <gtest/gtest.h>

#include <thread>

#include "FeatureExtractor.hpp"
#include "FlowTracker.hpp"
#include "TestPackets.hpp"

using namespace aifw;
using namespace aifw::test;
using namespace std::chrono_literals;

namespace {
PacketInfo pkt(const std::string& src, const std::string& dst, std::uint16_t sp, std::uint16_t dp, Direction d,
               Protocol proto = Protocol::TCP, std::uint8_t flags = tcpflags::ACK) {
    static thread_local std::vector<std::uint8_t> buf;  // holder payload-pekeren gyldig
    buf = ipv4(src, dst, proto, sp, dp, flags);
    return *FeatureExtractor::parse(buf, d);
}
}  // namespace

TEST(RunningStats, MeanAndStd) {
    RunningStats s;
    for (double x : {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0}) s.add(x);
    EXPECT_DOUBLE_EQ(s.mean(), 5.0);
    EXPECT_NEAR(s.stddev(), 2.138089935, 1e-6);  // utvalgs-std
}

TEST(FlowTracker, TracksBidirectionalFlow) {
    FlowTracker ft;
    auto t = Clock::now();
    ft.update(pkt("192.168.1.2", "1.1.1.1", 50000, 443, Direction::Outbound), t);
    ft.update(pkt("1.1.1.1", "192.168.1.2", 443, 50000, Direction::Inbound), t + 10ms);
    auto s = ft.update(pkt("192.168.1.2", "1.1.1.1", 50000, 443, Direction::Outbound), t + 20ms);
    ASSERT_TRUE(s);
    EXPECT_EQ(ft.size(), 1u);
    EXPECT_EQ(s->fwdPackets, 2u);
    EXPECT_EQ(s->bwdPackets, 1u);
    EXPECT_EQ(s->iatMs.count(), 2u);
    EXPECT_NEAR(s->iatMs.mean(), 10.0, 1e-6);
}

TEST(FlowTracker, SeparateFlowsForDifferentTuples) {
    FlowTracker ft;
    auto t = Clock::now();
    ft.update(pkt("192.168.1.2", "1.1.1.1", 50000, 443, Direction::Outbound), t);
    ft.update(pkt("192.168.1.2", "1.1.1.1", 50001, 443, Direction::Outbound), t);
    ft.update(pkt("192.168.1.2", "1.1.1.1", 50000, 443, Direction::Outbound, Protocol::UDP), t);
    EXPECT_EQ(ft.size(), 3u);
}

TEST(FlowTracker, ExpiresIdleFlowsByProtocol) {
    FlowTrackerConfig cfg;
    cfg.tcpIdleTimeout = 1000ms;
    cfg.udpIdleTimeout = 100ms;
    FlowTracker ft(cfg);
    auto t = Clock::now();
    ft.update(pkt("10.0.0.1", "10.0.0.2", 1, 2, Direction::Outbound, Protocol::TCP), t);
    ft.update(pkt("10.0.0.1", "10.0.0.2", 3, 4, Direction::Outbound, Protocol::UDP), t);
    std::size_t callbacks = 0;
    EXPECT_EQ(ft.expire(t + 200ms, [&](const FlowKey& k, const FlowStats&) {
        ++callbacks;
        EXPECT_EQ(k.protocol, Protocol::UDP);
    }), 1u);
    EXPECT_EQ(callbacks, 1u);
    EXPECT_EQ(ft.size(), 1u);
    EXPECT_EQ(ft.expire(t + 1500ms), 1u);
    EXPECT_EQ(ft.size(), 0u);
}

TEST(FlowTracker, ClosedFlowsExpireFaster) {
    FlowTrackerConfig cfg;
    cfg.closedTimeout = 50ms;
    FlowTracker ft(cfg);
    auto t = Clock::now();
    ft.update(pkt("10.0.0.1", "10.0.0.2", 1, 2, Direction::Outbound, Protocol::TCP, tcpflags::FIN | tcpflags::ACK), t);
    EXPECT_EQ(ft.expire(t + 60ms), 1u);
}

TEST(FlowTracker, RespectsMaxFlows) {
    FlowTrackerConfig cfg;
    cfg.maxFlows = 2;
    FlowTracker ft(cfg);
    auto t = Clock::now();
    EXPECT_TRUE(ft.update(pkt("10.0.0.1", "10.0.0.2", 1, 2, Direction::Outbound), t));
    EXPECT_TRUE(ft.update(pkt("10.0.0.1", "10.0.0.2", 3, 4, Direction::Outbound), t));
    EXPECT_FALSE(ft.update(pkt("10.0.0.1", "10.0.0.2", 5, 6, Direction::Outbound), t));
    EXPECT_EQ(ft.droppedNewFlows(), 1u);
    // Eksisterende flyter oppdateres fortsatt.
    EXPECT_TRUE(ft.update(pkt("10.0.0.1", "10.0.0.2", 1, 2, Direction::Outbound), t));
}

TEST(FlowTracker, CountsTcpFlags) {
    FlowTracker ft;
    auto t = Clock::now();
    ft.update(pkt("10.0.0.1", "10.0.0.2", 1, 2, Direction::Outbound, Protocol::TCP, tcpflags::SYN), t);
    ft.update(pkt("10.0.0.1", "10.0.0.2", 1, 2, Direction::Outbound, Protocol::TCP, tcpflags::PSH | tcpflags::ACK), t);
    auto s = ft.update(pkt("10.0.0.2", "10.0.0.1", 2, 1, Direction::Inbound, Protocol::TCP, tcpflags::RST), t);
    EXPECT_EQ(s->synCount, 1u);
    EXPECT_EQ(s->pshCount, 1u);
    EXPECT_EQ(s->rstCount, 1u);
    EXPECT_TRUE(s->rstSeen);
}

TEST(FlowTracker, ConcurrentUpdatesAreConsistent) {
    FlowTracker ft;
    const auto t = Clock::now();
    constexpr int kThreads = 8, kPerThread = 2000;
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&ft, t, i] {
            for (int n = 0; n < kPerThread; ++n) {
                auto buf = ipv4("10.0.0.1", "10.0.0.2", Protocol::TCP, static_cast<std::uint16_t>(1000 + (n % 50)), 80,
                                tcpflags::ACK);
                auto p = *FeatureExtractor::parse(buf, Direction::Outbound);
                ft.update(p, t + std::chrono::microseconds(i * kPerThread + n));
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(ft.size(), 50u);
    std::uint64_t total = 0;
    for (int port = 1000; port < 1050; ++port) {
        FlowKey k;
        k.localIp = *IpAddress::parse("10.0.0.1");
        k.remoteIp = *IpAddress::parse("10.0.0.2");
        k.localPort = static_cast<std::uint16_t>(port);
        k.remotePort = 80;
        k.protocol = Protocol::TCP;
        total += ft.get(k)->totalPackets();
    }
    EXPECT_EQ(total, static_cast<std::uint64_t>(kThreads * kPerThread));
}
