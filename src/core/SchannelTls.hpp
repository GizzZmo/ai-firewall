#pragma once
// Komplett Schannel TLS-klient med handshake og sertifikatvalidering.

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#ifdef _WIN32
#include <winsock2.h>
#include <schannel.h>
#include <security.h>
#endif

namespace aifw {

struct TlsConfig {
    std::string hostname;
    int timeoutMs{10000};
    bool verifyCert{true};
    DWORD protocols{SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT};
};

class SchannelTls {
public:
    SchannelTls();
    ~SchannelTls();

    // Koble til server med TLS
    bool connect(SOCKET sock, const TlsConfig& config);
    void disconnect();
    bool isConnected() const { return connected_; }

    // Kryptert I/O
    bool send(const uint8_t* data, size_t len);
    std::optional<std::vector<uint8_t>> recv(size_t maxLen = 65536);

    // Sertifikatinfo
    std::string getServerCertSubject() const { return certSubject_; }
    bool isCertValid() const { return certValid_; }

private:
    bool performHandshake(const std::string& hostname);
    bool validateCertificate();
    bool sendRaw(const void* data, size_t len);
    int recvRaw(void* data, size_t len);

#ifdef _WIN32
    SOCKET socket_{INVALID_SOCKET};
    CredHandle credHandle_{};
    CtxtHandle ctxtHandle_{};
    bool hasCred_{false};
    bool hasCtxt_{false};
    SecPkgContext_StreamSizes sizes_{};
#endif

    bool connected_{false};
    bool certValid_{false};
    std::string certSubject_;
    TlsConfig config_;
};

} // namespace aifw
