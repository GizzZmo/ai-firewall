#include <gtest/gtest.h>
#include "DnsParser.hpp"

using namespace aifw;

TEST(DnsParser, BuildQueryA) {
    auto query = DnsParser::buildQuery("example.com", 1, 0x1234);

    ASSERT_GE(query.size(), 12u);

    // Sjekk header
    EXPECT_EQ(query[0], 0x12);  // ID high
    EXPECT_EQ(query[1], 0x34);  // ID low
    EXPECT_EQ(query[2], 0x01);  // RD=1
    EXPECT_EQ(query[5], 0x01);  // QDCOUNT=1
}

TEST(DnsParser, BuildQueryPtr) {
    auto query = DnsParser::buildQuery("8.8.8.8.in-addr.arpa", 12);
    ASSERT_GE(query.size(), 12u);
}

TEST(DnsParser, ParseSimpleResponse) {
    // Minimal DNS-respons: header + A record for example.com -> 1.2.3.4
    std::vector<uint8_t> response = {
        // Header
        0x12, 0x34,  // ID
        0x81, 0x80,  // Flags: QR=1, RD=1, RA=1
        0x00, 0x01,  // QDCOUNT=1
        0x00, 0x01,  // ANCOUNT=1
        0x00, 0x00,  // NSCOUNT=0
        0x00, 0x00,  // ARCOUNT=0
        // Question: example.com A
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,  // Type A
        0x00, 0x01,  // Class IN
        // Answer: example.com A 1.2.3.4
        0xC0, 0x0C,  // Pointer to question name
        0x00, 0x01,  // Type A
        0x00, 0x01,  // Class IN
        0x00, 0x00, 0x00, 0x3C,  // TTL=60
        0x00, 0x04,  // RDLEN=4
        0x01, 0x02, 0x03, 0x04  // 1.2.3.4
    };

    auto msg = DnsParser::parse(response.data(), response.size());
    ASSERT_TRUE(msg.has_value());

    EXPECT_EQ(msg->id, 0x1234);
    EXPECT_EQ(msg->rcode, 0);
    EXPECT_EQ(msg->questions.size(), 1u);
    EXPECT_EQ(msg->answers.size(), 1u);

    EXPECT_EQ(msg->questions[0].name, "example.com");
    EXPECT_EQ(msg->questions[0].type, 1);

    EXPECT_EQ(msg->answers[0].name, "example.com");
    EXPECT_EQ(msg->answers[0].type, 1);
    EXPECT_EQ(msg->answers[0].ttl, 60u);
    EXPECT_EQ(msg->answers[0].rdataStr, "1.2.3.4");
}

TEST(DnsParser, ParseTruncated) {
    std::vector<uint8_t> truncated = {0x00, 0x01, 0x00, 0x00};  // Bare 4 bytes
    auto msg = DnsParser::parse(truncated.data(), truncated.size());
    EXPECT_FALSE(msg.has_value());
}

TEST(DnsParser, ParseEmpty) {
    auto msg = DnsParser::parse(nullptr, 0);
    EXPECT_FALSE(msg.has_value());
}

TEST(DnsParser, ParseNxDomain) {
    std::vector<uint8_t> response = {
        0x00, 0x01,  // ID
        0x81, 0x83,  // Flags: QR=1, RCODE=3 (NXDOMAIN)
        0x00, 0x01,  // QDCOUNT=1
        0x00, 0x00,  // ANCOUNT=0
        0x00, 0x00,  // NSCOUNT=0
        0x00, 0x00,  // ARCOUNT=0
        // Question
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01
    };

    auto msg = DnsParser::parse(response.data(), response.size());
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->rcode, 3);  // NXDOMAIN
    EXPECT_TRUE(msg->answers.empty());
}

TEST(DnsParser, ParseCompressionLoop) {
    // Ondsinnet pakke med kompresjonsløkke
    std::vector<uint8_t> malicious = {
        0x00, 0x01, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C,  // Pointer til seg selv
        0x00, 0x01, 0x00, 0x01
    };

    auto msg = DnsParser::parse(malicious.data(), malicious.size());
    // Bør ikke krasje eller henge
    EXPECT_FALSE(msg.has_value());
}
