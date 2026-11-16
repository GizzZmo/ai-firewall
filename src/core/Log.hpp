#pragma once

#include <filesystem>
#include <string>

namespace aifw {

/// Setter opp spdlog: farget konsoll + roterende fil (5 MB x 5). Trygt å kalle flere ganger.
void initLogging(const std::string& level, const std::filesystem::path& logFile, bool console = true);

}  // namespace aifw
