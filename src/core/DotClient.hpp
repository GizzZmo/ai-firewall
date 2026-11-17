#pragma once
// DNS-over-TLS (DoT) klient (RFC 7858).
// Kobler til port 853 med TLS og sender DNS wire-format.

#include <string>
#include <optional>
#include <vector>
#include <cstdint>

namespace aifw {

struct DotConfig {
    std::string server{"1.1.1.1"};  // Cloudflare DoT
    uint16_t port{853};
    int timeoutMs{5000};
    bool verifyCert{true};
};

struct DotAnswer {
    std::string name;
    uint16_t type{0};
    uint32_t ttl{0};
    std::string data;
};

class DotClient {
public:
    explicit DotClient(const DotConfig& config = {});
    ~DotClient();

    // Koble til DoT-server
    bool connect();
    void disconnect();
    bool isConnected() const;

    // Forward lookup (A)
    std::optional<std::vector<std::string>> resolve(const std::string& hostname);

    // Reverse lookup (PTR)
    std::optional<std::string> reverseLookup(uint32_t ipv4);

    // Generell spørring
    std::optional<std::vector<DotAnswer>> query(const std::string& name, uint16_t type);

private:
    // DNS wire-format
    std::vector<uint8_t> buildQuery(const std::string& name, uint16_t type) const;
    std::optional<std::vector<DotAnswer>> parseResponse(const std::vector<uint8_t>& data) const;

    // TLS-transport
    bool tlsConnect();
    bool tlsSend(const std::vector<uint8_t>& data);
    std::optional<std::vector<uint8_t>> tlsRecv();
    void tlsClose();

    static std::string ipv4ToPtr(uint32_t ip);

    DotConfig config_;
    bool connected_{false};

#ifdef _WIN32
    // Winsock + Schannel state
    uintptr_t socket_{0};
    void* credHandle_{nullptr};
    void* ctxtHandle_{nullptr};
#endif
};

} // namespace aifw
