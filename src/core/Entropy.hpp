#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace aifw {

/// Shannon-entropi i bits per byte (0.0 – 8.0). Høy entropi (> ~7.5) tyder på
/// kryptert/komprimert innhold; svært lav kan tyde på padding/flood.
[[nodiscard]] double shannonEntropy(std::span<const std::uint8_t> data) noexcept;

}  // namespace aifw
