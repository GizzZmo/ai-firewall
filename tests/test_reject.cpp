#include <gtest/gtest.h>

#include <iomanip>
#include <sstream>

#include "FeatureExtractor.hpp"
#include "RejectBuilder.hpp"
#include "TestPackets.hpp"

using namespace aifw;
using namespace aifw::test;

namespace {

std::string hexDump(const std::vector<std::uint8_t>& p) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < p.size(); ++i) {
        if (i) o << (i % 16 == 0 ? '\n' : ' ');
        o << std::setw(2) << static_cast<int>(p[i]);
    }
    return o.str();
}

void setSeqAck(std::vector<std::uint8_t>& pkt, std::size_t tcp, std::uint32_t seq, std::uint32_t ack) {
    auto put = [&](std::size_t off, std::uint32_t v) {
        pkt[off] = static_cast<std::uint8_t>(v >> 24);
        pkt[off + 1] = static_cast<std::uint8_t>(v >> 16);
        pkt[off + 2] = static_cast<std::uint8_t>(v >> 8);
        pkt[off + 3] = static_cast<std::uint8_t>(v);
    };
    put(tcp + 4, seq);
    put(tcp + 8, ack);
}

}  // namespace

TEST(RejectBuilder, Ipv4SynBecomesRstWithAck) {
    auto raw = ipv4("192.168.1.10", "93.184.216.34", Protocol::TCP, 50000, 443, tcpflags::SYN);
    setSeqAck(raw, 20, 0x11223344, 0);
    auto info = FeatureExtractor::parse(raw, Direction::Outbound);
    ASSERT_TRUE(info);
    EXPECT_EQ(info->tcpSeq, 0x11223344u);

    auto rst = buildTcpRst(*info);
    ASSERT_TRUE(rst);
    std::cout << "RST ipv4\n" << hexDump(*rst) << '\n';

    auto back = FeatureExtractor::parse(*rst, Direction::Inbound);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->srcIp.toString(), "93.184.216.34");
    EXPECT_EQ(back->dstIp.toString(), "192.168.1.10");
    EXPECT_EQ(back->srcPort, 443);
    EXPECT_EQ(back->dstPort, 50000);
    EXPECT_EQ(back->tcpFlags, tcpflags::RST | tcpflags::ACK);
    EXPECT_EQ(back->tcpSeq, 0u);
    EXPECT_EQ(back->tcpAck, 0x11223345u);  // SYN teller som ett oktett
    EXPECT_NE((rst->at(10) << 8) | rst->at(11), 0);  // IPv4-sjekksum satt
}

TEST(RejectBuilder, AckedSegmentRstUsesAckAsSeq) {
    std::vector<std::uint8_t> payload(10, 0x61);
    auto raw = ipv4("10.0.0.2", "10.0.0.1", Protocol::TCP, 1234, 80, tcpflags::ACK | tcpflags::PSH, payload);
    setSeqAck(raw, 20, 100, 200);
    auto info = FeatureExtractor::parse(raw, Direction::Inbound);
    ASSERT_TRUE(info);
    auto rst = buildTcpRst(*info);
    ASSERT_TRUE(rst);
    auto back = FeatureExtractor::parse(*rst, Direction::Outbound);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->tcpFlags, tcpflags::RST);
    EXPECT_EQ(back->tcpSeq, 200u);
    EXPECT_EQ(back->tcpAck, 0u);
}

TEST(RejectBuilder, Ipv6ExtensionHeaderRst) {
    auto raw = ipv6("2001:db8::10", "2001:db8::1", Protocol::TCP, 40000, 22, tcpflags::SYN, {}, true);
    // Hop-by-hop (8) ligger foran TCP, så sekvensen starter ved offset 48.
    setSeqAck(raw, 48, 7, 0);
    auto info = FeatureExtractor::parse(raw, Direction::Outbound);
    ASSERT_TRUE(info);
    EXPECT_EQ(info->tcpSeq, 7u);
    auto rst = buildTcpRst(*info);
    ASSERT_TRUE(rst);
    std::cout << "RST ipv6\n" << hexDump(*rst) << '\n';
    auto back = FeatureExtractor::parse(*rst, Direction::Inbound);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->srcIp, IpAddress::parse("2001:db8::1"));
    EXPECT_EQ(back->dstIp, IpAddress::parse("2001:db8::10"));
    EXPECT_EQ(back->tcpFlags, tcpflags::RST | tcpflags::ACK);
    EXPECT_EQ(back->tcpAck, 8u);
    EXPECT_EQ(rst->size(), 60u);  // IPv6 + TCP, uten extension header
}

TEST(RejectBuilder, UdpPortUnreachableQuotesOriginal) {
    auto raw = ipv4("10.1.1.1", "10.2.2.2", Protocol::UDP, 53000, 51820, 0, {1, 2, 3, 4});
    auto info = FeatureExtractor::parse(raw, Direction::Outbound);
    ASSERT_TRUE(info);
    auto icmp = buildPortUnreachable(*info, raw);
    ASSERT_TRUE(icmp);
    std::cout << "ICMP port unreachable\n" << hexDump(*icmp) << '\n';
    auto back = FeatureExtractor::parse(*icmp, Direction::Inbound);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->protocol, Protocol::ICMP);
    EXPECT_EQ(back->srcPort, 3);  // type
    EXPECT_EQ(back->dstPort, 3);  // kode
    EXPECT_EQ(back->srcIp.toString(), "10.2.2.2");
    // Sitatet starter rett etter ICMP-headeren (20 + 8).
    ASSERT_GE(icmp->size(), 28u + 20u);
    EXPECT_EQ(icmp->at(28), 0x45);
    EXPECT_EQ(icmp->at(28 + 20), static_cast<std::uint8_t>(53000 >> 8));
}
