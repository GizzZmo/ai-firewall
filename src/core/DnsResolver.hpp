#pragma once

#include <string>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace aifw {

// Enkel reverse-DNS-oppslag med cache.
// Brukes i logger for å vise domenenavn i stedet for bare IP.
class DnsResolver {
public:
    DnsResolver();
    explicit DnsResolver(std::chrono::seconds cacheTtl);

    // Reverse lookup. Returnerer hostname eller nullopt ved feil/timeout.
    // Resultat caches.
    std::optional<std::string> reverseLookup(uint32_t ipv4);

    // IPv6-variant (16 bytes)
    std::optional<std::string> reverseLookupV6(const uint8_t addr[16]);

    // Tøm cache
    void clearCache();

    size_t cacheSize() const;

private:
    struct CacheEntry {
        std::string hostname;
        std::chrono::steady_clock::time_point expires;
    };

    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, CacheEntry> cacheV4_;
    std::chrono::seconds ttl_;

    std::optional<std::string> lookupUncached(uint32_t ipv4);
};

} // namespace aifw
