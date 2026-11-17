#include "DotClient.hpp"

#include <cstring>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <schannel.h>
#include <security.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#endif

namespace aifw {

DotClient::DotClient(const DotConfig& config) : config_(config) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

DotClient::~DotClient() {
    disconnect();
#ifdef _WIN32
    WSACleanup();
#endif
}

std::string DotClient::ipv4ToPtr(uint32_t ip) {
    std::ostringstream oss;
    oss << ((ip >> 0) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 24) & 0xFF) << ".in-addr.arpa";
    return oss.str();
}

std::vector<uint8_t> DotClient::buildQuery(const std::string& name, uint16_t type) const {
    std::vector<uint8_t> query;

    // DNS header (12 bytes)
    uint16_t id = 0x1234;  // Transaksjons-ID
    query.push_back(id >> 8);
    query.push_back(id & 0xFF);
    query.push_back(0x01);  // Flags: RD=1
    query.push_back(0x00);
    query.push_back(0x00);  // QDCOUNT = 1
    query.push_back(0x01);
    query.push_back(0x00);  // ANCOUNT = 0
    query.push_back(0x00);
    query.push_back(0x00);  // NSCOUNT = 0
    query.push_back(0x00);
    query.push_back(0x00);  // ARCOUNT = 0
    query.push_back(0x00);

    // QNAME: encode domain name
    std::istringstream iss(name);
    std::string label;
    while (std::getline(iss, label, '.')) {
        if (label.empty()) continue;
        query.push_back(static_cast<uint8_t>(label.size()));
        for (char c : label) {
            query.push_back(static_cast<uint8_t>(c));
        }
    }
    query.push_back(0x00);  // Null terminator

    // QTYPE
    query.push_back(type >> 8);
    query.push_back(type & 0xFF);

    // QCLASS = IN (1)
    query.push_back(0x00);
    query.push_back(0x01);

    return query;
}

std::optional<std::vector<DotAnswer>> DotClient::parseResponse(const std::vector<uint8_t>& data) const {
    if (data.size() < 12) return std::nullopt;

    // Sjekk RCODE (bits 0-3 i byte 3)
    uint8_t rcode = data[3] & 0x0F;
    if (rcode != 0) return std::nullopt;  // Ikke NOERROR

    uint16_t ancount = (data[6] << 8) | data[7];
    if (ancount == 0) return std::nullopt;

    // Forenklet parsing: hopp over spørsmålsseksjonen og les første svar
    // Full parsing krever håndtering av komprimering (RFC 1035)
    std::vector<DotAnswer> answers;

    // Finn start av answer-seksjon (etter header + question)
    size_t pos = 12;
    // Hopp over QNAME
    while (pos < data.size() && data[pos] != 0) {
        pos += data[pos] + 1;
    }
    pos += 5;  // Null + QTYPE + QCLASS

    // Les svar (forenklet)
    for (uint16_t i = 0; i < ancount && pos + 12 < data.size(); ++i) {
        DotAnswer ans;

        // Hopp over NAME (kan være pointer)
        if ((data[pos] & 0xC0) == 0xC0) {
            pos += 2;  // Pointer
        } else {
            while (pos < data.size() && data[pos] != 0) {
                pos += data[pos] + 1;
            }
            pos++;
        }

        if (pos + 10 > data.size()) break;

        ans.type = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        pos += 2;  // CLASS
        ans.ttl = (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        uint16_t rdlen = (data[pos] << 8) | data[pos + 1];
        pos += 2;

        if (pos + rdlen > data.size()) break;

        if (ans.type == 1 && rdlen == 4) {  // A record
            char buf[16];
            snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
            ans.data = buf;
        } else if (ans.type == 12) {  // PTR
            // Forenklet: les som tekst
            std::string ptr;
            size_t p = pos;
            while (p < pos + rdlen && data[p] != 0) {
                uint8_t len = data[p++];
                if (p + len > pos + rdlen) break;
                if (!ptr.empty()) ptr += ".";
                ptr.append(reinterpret_cast<const char*>(&data[p]), len);
                p += len;
            }
            ans.data = ptr;
        }

        pos += rdlen;
        answers.push_back(std::move(ans));
    }

    return answers.empty() ? std::nullopt : std::optional(answers);
}

bool DotClient::connect() {
    if (connected_) return true;
    return tlsConnect();
}

void DotClient::disconnect() {
    tlsClose();
    connected_ = false;
}

bool DotClient::isConnected() const {
    return connected_;
}

bool DotClient::tlsConnect() {
#ifdef _WIN32
    // Opprett TCP-socket
    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) return false;

    // Timeout
    DWORD timeout = config_.timeoutMs;
    setsockopt(static_cast<SOCKET>(socket_), SOL_SOCKET, SO_RCVTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(static_cast<SOCKET>(socket_), SOL_SOCKET, SO_SNDTIMEO,
        reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    // Koble til
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    inet_pton(AF_INET, config_.server.c_str(), &addr.sin_addr);

    if (::connect(static_cast<SOCKET>(socket_),
            reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(static_cast<SOCKET>(socket_));
        socket_ = 0;
        return false;
    }

    // Schannel TLS handshake (forenklet – produksjon krever full implementasjon)
    // Se docs/DNS_OVER_TLS.md for detaljer

    connected_ = true;
    return true;
#else
    return false;
#endif
}

bool DotClient::tlsSend(const std::vector<uint8_t>& data) {
#ifdef _WIN32
    if (!connected_ || socket_ == 0) return false;

    // DoT bruker 2-byte lengde-prefix
    uint16_t len = htons(static_cast<uint16_t>(data.size()));
    if (send(static_cast<SOCKET>(socket_), reinterpret_cast<const char*>(&len), 2, 0) != 2) {
        return false;
    }
    return send(static_cast<SOCKET>(socket_),
        reinterpret_cast<const char*>(data.data()),
        static_cast<int>(data.size()), 0) == static_cast<int>(data.size());
#else
    (void)data;
    return false;
#endif
}

std::optional<std::vector<uint8_t>> DotClient::tlsRecv() {
#ifdef _WIN32
    if (!connected_ || socket_ == 0) return std::nullopt;

    // Les 2-byte lengde
    uint16_t len = 0;
    if (recv(static_cast<SOCKET>(socket_), reinterpret_cast<char*>(&len), 2, MSG_WAITALL) != 2) {
        return std::nullopt;
    }
    len = ntohs(len);
    if (len == 0 || len > 65535) return std::nullopt;

    std::vector<uint8_t> data(len);
    if (recv(static_cast<SOCKET>(socket_),
            reinterpret_cast<char*>(data.data()), len, MSG_WAITALL) != len) {
        return std::nullopt;
    }
    return data;
#else
    return std::nullopt;
#endif
}

void DotClient::tlsClose() {
#ifdef _WIN32
    if (socket_ != 0) {
        closesocket(static_cast<SOCKET>(socket_));
        socket_ = 0;
    }
#endif
}

std::optional<std::vector<DotAnswer>> DotClient::query(const std::string& name, uint16_t type) {
    if (!connected_ && !connect()) return std::nullopt;

    auto queryData = buildQuery(name, type);
    if (!tlsSend(queryData)) return std::nullopt;

    auto response = tlsRecv();
    if (!response) return std::nullopt;

    return parseResponse(*response);
}

std::optional<std::vector<std::string>> DotClient::resolve(const std::string& hostname) {
    auto answers = query(hostname, 1);  // A record
    if (!answers) return std::nullopt;

    std::vector<std::string> ips;
    for (const auto& a : *answers) {
        if (a.type == 1 && !a.data.empty()) {
            ips.push_back(a.data);
        }
    }
    return ips.empty() ? std::nullopt : std::optional(ips);
}

std::optional<std::string> DotClient::reverseLookup(uint32_t ipv4) {
    std::string ptr = ipv4ToPtr(ipv4);
    auto answers = query(ptr, 12);  // PTR record
    if (!answers || answers->empty()) return std::nullopt;
    return answers->front().data;
}

} // namespace aifw
