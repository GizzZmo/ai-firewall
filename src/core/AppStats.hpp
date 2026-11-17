#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <cstdint>

namespace aifw {

// Per-app-statistikk (for GUI og «spør brukeren»-dialog).
struct AppStat {
    std::string path;
    std::uint64_t packetsAllowed{0};
    std::uint64_t packetsBlocked{0};
    std::uint64_t bytesAllowed{0};
    std::uint64_t bytesBlocked{0};
    std::uint64_t lastSeenMs{0};
    bool userPrompted{false};   // har vi allerede spurt brukeren?
    bool userAllowed{false};    // brukerens svar (hvis prompted)
};

class AppStats {
public:
    void record(const std::string& appPath, bool allowed, std::uint64_t bytes, std::uint64_t nowMs);

    // Returnerer true hvis vi bør spørre brukeren (ny app, ikke spurt før)
    bool shouldPrompt(const std::string& appPath) const;

    void markPrompted(const std::string& appPath, bool userAllowed);

    std::unordered_map<std::string, AppStat> snapshot() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, AppStat> stats_;
};

} // namespace aifw
