#include "VerdictCache.hpp"

namespace aifw {

void VerdictCache::put(const FlowKey& key, Verdict v, float score, TimePoint expires) {
    std::lock_guard lock(mutex_);
    if (auto it = map_.find(key); it != map_.end()) {
        it->second.value = {v, score, expires};
        lru_.splice(lru_.begin(), lru_, it->second.lruIt);
        return;
    }
    if (map_.size() >= max_) {
        map_.erase(lru_.back());
        lru_.pop_back();
    }
    lru_.push_front(key);
    map_.emplace(key, Entry{{v, score, expires}, lru_.begin()});
}

std::optional<CachedVerdict> VerdictCache::get(const FlowKey& key, TimePoint now) {
    std::lock_guard lock(mutex_);
    auto it = map_.find(key);
    if (it == map_.end()) return std::nullopt;
    if (now >= it->second.value.expires) {
        lru_.erase(it->second.lruIt);
        map_.erase(it);
        return std::nullopt;
    }
    lru_.splice(lru_.begin(), lru_, it->second.lruIt);
    return it->second.value;
}

bool VerdictCache::erase(const FlowKey& key) {
    std::lock_guard lock(mutex_);
    auto it = map_.find(key);
    if (it == map_.end()) return false;
    lru_.erase(it->second.lruIt);
    map_.erase(it);
    return true;
}

void VerdictCache::clear() {
    std::lock_guard lock(mutex_);
    map_.clear();
    lru_.clear();
}

std::size_t VerdictCache::size() const {
    std::lock_guard lock(mutex_);
    return map_.size();
}

}  // namespace aifw
