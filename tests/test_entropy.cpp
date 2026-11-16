#include <gtest/gtest.h>

#include <numeric>
#include <random>
#include <vector>

#include "Entropy.hpp"

using aifw::shannonEntropy;

TEST(Entropy, EmptyIsZero) { EXPECT_DOUBLE_EQ(shannonEntropy({}), 0.0); }

TEST(Entropy, ConstantIsZero) {
    std::vector<std::uint8_t> v(1000, 0x41);
    EXPECT_DOUBLE_EQ(shannonEntropy(v), 0.0);
}

TEST(Entropy, TwoSymbolsIsOneBit) {
    std::vector<std::uint8_t> v;
    for (int i = 0; i < 500; ++i) { v.push_back(0); v.push_back(1); }
    EXPECT_NEAR(shannonEntropy(v), 1.0, 1e-12);
}

TEST(Entropy, AllBytesUniformIsEightBits) {
    std::vector<std::uint8_t> v(256 * 4);
    for (std::size_t i = 0; i < v.size(); ++i) v[i] = static_cast<std::uint8_t>(i);
    EXPECT_NEAR(shannonEntropy(v), 8.0, 1e-12);
}

TEST(Entropy, RandomDataIsHighTextIsLower) {
    std::mt19937 rng(42);
    std::vector<std::uint8_t> rnd(4096);
    for (auto& b : rnd) b = static_cast<std::uint8_t>(rng());
    EXPECT_GT(shannonEntropy(rnd), 7.9);
    const std::string text = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    const double h = shannonEntropy(std::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    EXPECT_GT(h, 3.0);
    EXPECT_LT(h, 5.5);
}
