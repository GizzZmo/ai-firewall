#pragma once
// DNS-over-HTTPS (DoH) klient med JSON API.
// Støtter Cloudflare og Google Public DNS.

#include <string>
#include <optional>
#include <vector>
#include <cstdint>

namespace aifw {

enum class DohProvider {
    Cloudflare,  // https://cloudflare-dns.com/dns-query
    Google       // https://dns.google/resolve
};

struct DohConfig {
    DohProvider provider{DohProvider::Cloudflare};
    int timeoutMs{3000};
    bool dnssec{false};  // Be om DNSSEC-validering
};

struct DohAnswer {
    std::string name;
    uint16_t type{0};
    uint32_t ttl{0};
    std::string data;
};

class DohClient {
public:
    explicit DohClient(const DohConfig& config = {});

    // Forward lookup (A/AAAA)
    std::optional<std::vector<std::string>> resolve(const std::string& hostname);

    // Reverse lookup (PTR)
    std::optional<std::string> reverseLookup(uint32_t ipv4);
    std::optional<std::string> reverseLookupV6(const uint8_t addr[16]);

    // Generell spørring
    std::optional<std::vector<DohAnswer>> query(const std::string& name, const std::string& type);

private:
    std::string buildUrl(const std::string& name, const std::string& type) const;
    std::optional<std::string> httpGet(const std::string& url) const;
    std::optional<std::vector<DohAnswer>> parseResponse(const std::string& json) const;

    static std::string ipv4ToPtr(uint32_t ip);
    static std::string ipv6ToPtr(const uint8_t addr[16]);

    DohConfig config_;
};

} // namespace aifw
