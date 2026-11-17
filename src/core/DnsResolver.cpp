#include "DnsResolver.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

#include <cstring>

namespace aifw {

DnsResolver::DnsResolver()
    : DnsResolver(std::chrono::seconds(300)) {}

DnsResolver::DnsResolver(std::chrono::seconds cacheTtl)
    : ttl_(cacheTtl) {}

std::optional<std::string> DnsResolver::reverseLookup(uint32_t ipv4) {
    {
        std::lock_guard lock(mutex_);
        auto it = cacheV4_.find(ipv4);
        if (it != cacheV4_.end()) {
            if (std::chrono::steady_clock::now() < it->second.expires) {
                return it->second.hostname;
            }
            cacheV4_.erase(it);
        }
    }

    auto result = lookupUncached(ipv4);
    if (result) {
        std::lock_guard lock(mutex_);
        cacheV4_[ipv4] = CacheEntry{
            *result,
            std::chrono::steady_clock::now() + ttl_
        };
    }
    return result;
}

std::optional<std::string> DnsResolver::lookupUncached(uint32_t ipv4) {
#ifdef _WIN32
    // Winsock må være initialisert av kalleren (eller vi gjør det her)
    static bool wsaInit = false;
    if (!wsaInit) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) wsaInit = true;
    }
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(ipv4);

    char host[NI_MAXHOST] = {};
    int rc = getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
                         host, sizeof(host), nullptr, 0, NI_NAMEREQD);

    if (rc != 0 || host[0] == '\0') {
        return std::nullopt;
    }
    return std::string(host);
}

std::optional<std::string> DnsResolver::reverseLookupV6(const uint8_t addr[16]) {
    // Enkel implementasjon – kan utvides med egen cache
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    std::memcpy(&sa.sin6_addr, addr, 16);

    char host[NI_MAXHOST] = {};
    int rc = getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa),
                         host, sizeof(host), nullptr, 0, NI_NAMEREQD);
    if (rc != 0 || host[0] == '\0') return std::nullopt;
    return std::string(host);
}

void DnsResolver::clearCache() {
    std::lock_guard lock(mutex_);
    cacheV4_.clear();
}

size_t DnsResolver::cacheSize() const {
    std::lock_guard lock(mutex_);
    return cacheV4_.size();
}

} // namespace aifw
