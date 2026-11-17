// Eksporterer utløpte flyter anonymisert for trening av egen modell.
#pragma once

#include <filesystem>
#include <fstream>
#include <mutex>

#include <nlohmann/json.hpp>

#include "FlowTracker.hpp"
#include "Types.hpp"

namespace aifw {

class FlowExporter {
public:
    explicit FlowExporter(std::filesystem::path path);

    /// Kalles fra housekeeping når en flyt utløper. Anonymiserer IP-er.
    void onExpired(const FlowKey& key, const FlowStats& stats);

    void flush();

private:
    std::filesystem::path path_;
    std::mutex mutex_;
    std::ofstream out_;
    std::size_t count_{0};
};

}  // namespace aifw
