// Fast-path cache: flyt -> verdikt med TTL og LRU-utkasting. O(1) oppslag.
#pragma once

#include <chrono>
#include <list>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "Types.hpp"

namespace aifw {

struct CachedVerdict {
    Verdict verdict{Verdict::Unknown};
    float score{0.0f};
    TimePoint expires{};
};

class VerdictCache {
public:
    explicit VerdictCache(std::size_t maxEntries = 100'000) : max_(maxEntries ? maxEntries : 1) {}

    void put(const FlowKey& key, Verdict v, float score, TimePoint expires);
    /// Returnerer verdikt hvis det finnes og ikke er utløpt (utløpte fjernes ved oppslag).
    [[nodiscard]] std::optional<CachedVerdict> get(const FlowKey& key, TimePoint now);
    bool erase(const FlowKey& key);
    void clear();
    [[nodiscard]] std::size_t size() const;

private:
    using LruList = std::list<FlowKey>;
    struct Entry {
        CachedVerdict value;
        LruList::iterator lruIt;
    };
    std::size_t max_;
    mutable std::mutex mutex_;
    LruList lru_;  // front = sist brukt
    std::unordered_map<FlowKey, Entry, FlowKeyHash> map_;
};

}  // namespace aifw
