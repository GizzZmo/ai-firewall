#include <gtest/gtest.h>

#include "VerdictCache.hpp"

using namespace aifw;
using namespace std::chrono_literals;

namespace {
FlowKey key(std::uint16_t port) {
    FlowKey k;
    k.localIp = IpAddress::v4(0x0A000001);
    k.remoteIp = IpAddress::v4(0x08080808);
    k.localPort = port;
    k.remotePort = 443;
    k.protocol = Protocol::TCP;
    return k;
}
}  // namespace

TEST(VerdictCache, PutGetAndExpiry) {
    VerdictCache c(10);
    auto now = Clock::now();
    c.put(key(1), Verdict::Block, 0.95f, now + 1s);
    auto v = c.get(key(1), now);
    ASSERT_TRUE(v);
    EXPECT_EQ(v->verdict, Verdict::Block);
    EXPECT_FLOAT_EQ(v->score, 0.95f);
    EXPECT_FALSE(c.get(key(1), now + 2s));
    EXPECT_EQ(c.size(), 0u);  // utløpt oppføring fjernet
}

TEST(VerdictCache, EvictsLeastRecentlyUsed) {
    VerdictCache c(2);
    auto now = Clock::now();
    c.put(key(1), Verdict::Allow, 0, now + 1h);
    c.put(key(2), Verdict::Allow, 0, now + 1h);
    ASSERT_TRUE(c.get(key(1), now));  // 1 blir nyest
    c.put(key(3), Verdict::Allow, 0, now + 1h);
    EXPECT_TRUE(c.get(key(1), now));
    EXPECT_FALSE(c.get(key(2), now));
    EXPECT_TRUE(c.get(key(3), now));
    EXPECT_EQ(c.size(), 2u);
}

TEST(VerdictCache, OverwriteAndErase) {
    VerdictCache c(4);
    auto now = Clock::now();
    c.put(key(1), Verdict::Allow, 0.1f, now + 1h);
    c.put(key(1), Verdict::Block, 0.99f, now + 1h);
    EXPECT_EQ(c.get(key(1), now)->verdict, Verdict::Block);
    EXPECT_EQ(c.size(), 1u);
    EXPECT_TRUE(c.erase(key(1)));
    EXPECT_FALSE(c.erase(key(1)));
}
