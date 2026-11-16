#include "Entropy.hpp"

#include <array>
#include <cmath>

namespace aifw {

double shannonEntropy(std::span<const std::uint8_t> data) noexcept {
    if (data.empty()) return 0.0;
    std::array<std::size_t, 256> counts{};
    for (auto b : data) ++counts[b];
    const double n = static_cast<double>(data.size());
    double h = 0.0;
    for (auto c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / n;
        h -= p * std::log2(p);
    }
    return h;
}

}  // namespace aifw
