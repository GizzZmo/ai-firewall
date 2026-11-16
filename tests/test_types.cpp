#include <gtest/gtest.h>

#include "Types.hpp"

using namespace aifw;

TEST(IpAddress, ParsesIpv4) {
    auto a = IpAddress::parse("192.168.1.20");
    ASSERT_TRUE(a);
    EXPECT_EQ(a->version, 4);
    EXPECT_EQ(a->toString(), "192.168.1.20");
    EXPECT_EQ(*a, IpAddress::v4(0xC0A80114));
}

TEST(IpAddress, RejectsBadIpv4) {
    for (const char* s : {"256.1.1.1", "1.2.3", "1.2.3.4.5", "a.b.c.d", "", "1..2.3", "1.2.3.4 "})
        EXPECT_FALSE(IpAddress::parse(s)) << s;
}

TEST(IpAddress, ParsesIpv6Forms) {
    auto a = IpAddress::parse("2001:db8::1");
    ASSERT_TRUE(a);
    EXPECT_EQ(a->version, 6);
    EXPECT_EQ(a->bytes[0], 0x20);
    EXPECT_EQ(a->bytes[1], 0x01);
    EXPECT_EQ(a->bytes[15], 0x01);
    EXPECT_EQ(a->toString(), "2001:db8:0:0:0:0:0:1");

    auto loop = IpAddress::parse("::1");
    ASSERT_TRUE(loop);
    EXPECT_EQ(loop->bytes[15], 1);
    auto any = IpAddress::parse("::");
    ASSERT_TRUE(any);
    auto ll = IpAddress::parse("fe80::");
    ASSERT_TRUE(ll);
    EXPECT_EQ(ll->bytes[0], 0xfe);
    auto mapped = IpAddress::parse("::ffff:10.0.0.1");
    ASSERT_TRUE(mapped);
    EXPECT_EQ(mapped->bytes[10], 0xff);
    EXPECT_EQ(mapped->bytes[12], 10);
    EXPECT_TRUE(IpAddress::parse("1:2:3:4:5:6:7:8"));
}

TEST(IpAddress, RejectsBadIpv6) {
    for (const char* s : {"1::2::3", "12345::", "1:2:3:4:5:6:7:8:9", "1:2:3", "g::1", "1:2:3:4:5:6:7:"})
        EXPECT_FALSE(IpAddress::parse(s)) << s;
}

TEST(Cidr, ContainsIpv4) {
    auto c = Cidr::parse("10.0.0.0/8").value();
    EXPECT_TRUE(c.contains(*IpAddress::parse("10.255.1.2")));
    EXPECT_FALSE(c.contains(*IpAddress::parse("11.0.0.1")));
    auto c2 = Cidr::parse("192.168.1.128/25").value();
    EXPECT_TRUE(c2.contains(*IpAddress::parse("192.168.1.200")));
    EXPECT_FALSE(c2.contains(*IpAddress::parse("192.168.1.127")));
    auto host = Cidr::parse("8.8.8.8").value();
    EXPECT_EQ(host.prefix, 32);
    EXPECT_TRUE(host.contains(*IpAddress::parse("8.8.8.8")));
    auto all = Cidr::parse("0.0.0.0/0").value();
    EXPECT_TRUE(all.contains(*IpAddress::parse("1.2.3.4")));
}

TEST(Cidr, NormalisesHostBitsAndRejectsBad) {
    auto c = Cidr::parse("10.1.2.3/8").value();
    EXPECT_EQ(c.network.toString(), "10.0.0.0");
    EXPECT_FALSE(Cidr::parse("10.0.0.0/33"));
    EXPECT_FALSE(Cidr::parse("10.0.0.0/x"));
}

TEST(Cidr, Ipv6AndVersionMismatch) {
    auto c = Cidr::parse("fe80::/10").value();
    EXPECT_TRUE(c.contains(*IpAddress::parse("fe80::1234")));
    EXPECT_TRUE(c.contains(*IpAddress::parse("febf::1")));
    EXPECT_FALSE(c.contains(*IpAddress::parse("fec0::1")));
    EXPECT_FALSE(c.contains(*IpAddress::parse("10.0.0.1")));
}

TEST(FlowKey, BothDirectionsMapToSameKey) {
    PacketInfo out;
    out.srcIp = *IpAddress::parse("192.168.1.10");
    out.dstIp = *IpAddress::parse("1.1.1.1");
    out.srcPort = 50000;
    out.dstPort = 443;
    out.protocol = Protocol::TCP;
    out.direction = Direction::Outbound;
    PacketInfo in = out;
    std::swap(in.srcIp, in.dstIp);
    std::swap(in.srcPort, in.dstPort);
    in.direction = Direction::Inbound;
    EXPECT_EQ(out.flowKey(), in.flowKey());
    EXPECT_EQ(FlowKeyHash{}(out.flowKey()), FlowKeyHash{}(in.flowKey()));
    EXPECT_EQ(out.flowKey().remotePort, 443);
}
