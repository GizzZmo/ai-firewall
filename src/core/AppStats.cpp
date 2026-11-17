#include "AppStats.hpp"

namespace aifw {

void AppStats::record(const std::string& appPath, bool allowed, std::uint64_t bytes, std::uint64_t nowMs) {
    if (appPath.empty()) return;
    std::lock_guard lock(mutex_);
    auto& s = stats_[appPath];
    s.path = appPath;
    s.lastSeenMs = nowMs;
    if (allowed) {
        s.packetsAllowed++;
        s.bytesAllowed += bytes;
    } else {
        s.packetsBlocked++;
        s.bytesBlocked += bytes;
    }
}

bool AppStats::shouldPrompt(const std::string& appPath) const {
    std::lock_guard lock(mutex_);
    auto it = stats_.find(appPath);
    if (it == stats_.end()) return true; // helt ny
    return !it->second.userPrompted;
}

void AppStats::markPrompted(const std::string& appPath, bool userAllowed) {
    std::lock_guard lock(mutex_);
    auto& s = stats_[appPath];
    s.userPrompted = true;
    s.userAllowed = userAllowed;
}

std::unordered_map<std::string, AppStat> AppStats::snapshot() const {
    std::lock_guard lock(mutex_);
    return stats_;
}

} // namespace aifw
