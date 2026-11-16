#include "Log.hpp"

#include <memory>
#include <vector>

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace aifw {

void initLogging(const std::string& level, const std::filesystem::path& logFile, bool console) {
    std::vector<spdlog::sink_ptr> sinks;
    if (console) sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    if (!logFile.empty()) {
        try {
            if (logFile.has_parent_path()) std::filesystem::create_directories(logFile.parent_path());
            sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(logFile.string(), 5 * 1024 * 1024, 5));
        } catch (const std::exception& e) {
            // Logging til fil skal aldri hindre oppstart.
            if (sinks.empty()) sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
            spdlog::default_logger()->warn("kan ikke åpne loggfil {}: {}", logFile.string(), e.what());
        }
    }
    auto logger = std::make_shared<spdlog::logger>("aifw", sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::from_str(level));
    logger->set_pattern("%Y-%m-%d %H:%M:%S.%e [%^%l%$] [t%t] %v");
    logger->flush_on(spdlog::level::warn);
    spdlog::set_default_logger(logger);
}

}  // namespace aifw
