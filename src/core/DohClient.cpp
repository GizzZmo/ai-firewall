#include "DohClient.hpp"

#include <sstream>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace aifw {

DohClient::DohClient(const DohConfig& config) : config_(config) {}

std::string DohClient::buildUrl(const std::string& name, const std::string& type) const {
    std::string base;
    switch (config_.provider) {
        case DohProvider::Cloudflare:
            base = "https://cloudflare-dns.com/dns-query";
            break;
        case DohProvider::Google:
            base = "https://dns.google/resolve";
            break;
    }

    std::ostringstream url;
    url << base << "?name=" << name << "&type=" << type;
    if (config_.dnssec) {
        url << "&do=1";
    }
    return url.str();
}

std::string DohClient::ipv4ToPtr(uint32_t ip) {
    // Konverter til in-addr.arpa format
    std::ostringstream oss;
    oss << ((ip >> 0) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 24) & 0xFF) << ".in-addr.arpa";
    return oss.str();
}

std::string DohClient::ipv6ToPtr(const uint8_t addr[16]) {
    // Konverter til ip6.arpa format (nibble-reversed)
    std::ostringstream oss;
    for (int i = 15; i >= 0; --i) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%x.%x.", addr[i] & 0xF, (addr[i] >> 4) & 0xF);
        oss << buf;
    }
    oss << "ip6.arpa";
    return oss.str();
}

std::optional<std::string> DohClient::httpGet(const std::string& url) const {
#ifdef _WIN32
    // Parse URL
    std::wstring wurl(url.begin(), url.end());
    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[1024] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        return std::nullopt;
    }

    HINTERNET session = WinHttpOpen(L"AiFirewall/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return std::nullopt;

    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return std::nullopt;
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"GET", path,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::nullopt;
    }

    // Sett Accept-header for JSON
    WinHttpAddRequestHeaders(request, L"Accept: application/dns-json",
        (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD);

    // Timeout
    WinHttpSetTimeouts(request, config_.timeoutMs, config_.timeoutMs,
        config_.timeoutMs, config_.timeoutMs);

    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, nullptr)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::nullopt;
    }

    std::string response;
    DWORD bytesRead = 0;
    char buffer[4096];
    while (WinHttpReadData(request, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        response.append(buffer, bytesRead);
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    return response.empty() ? std::nullopt : std::optional<std::string>(response);
#else
    (void)url;
    return std::nullopt;
#endif
}

std::optional<std::vector<DohAnswer>> DohClient::parseResponse(const std::string& json) const {
    try {
        auto j = nlohmann::json::parse(json);

        // Sjekk status (0 = NOERROR)
        if (j.value("Status", -1) != 0) {
            return std::nullopt;
        }

        if (!j.contains("Answer") || !j["Answer"].is_array()) {
            return std::nullopt;
        }

        std::vector<DohAnswer> answers;
        for (const auto& a : j["Answer"]) {
            DohAnswer ans;
            ans.name = a.value("name", "");
            ans.type = a.value("type", 0);
            ans.ttl = a.value("TTL", 0);
            ans.data = a.value("data", "");
            answers.push_back(std::move(ans));
        }
        return answers;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<DohAnswer>> DohClient::query(const std::string& name, const std::string& type) {
    std::string url = buildUrl(name, type);
    auto response = httpGet(url);
    if (!response) return std::nullopt;
    return parseResponse(*response);
}

std::optional<std::vector<std::string>> DohClient::resolve(const std::string& hostname) {
    auto answers = query(hostname, "A");
    if (!answers) return std::nullopt;

    std::vector<std::string> ips;
    for (const auto& a : *answers) {
        if (a.type == 1) {  // A record
            ips.push_back(a.data);
        }
    }
    return ips.empty() ? std::nullopt : std::optional(ips);
}

std::optional<std::string> DohClient::reverseLookup(uint32_t ipv4) {
    std::string ptr = ipv4ToPtr(ipv4);
    auto answers = query(ptr, "PTR");
    if (!answers || answers->empty()) return std::nullopt;

    // Fjern trailing dot fra hostname
    std::string hostname = answers->front().data;
    if (!hostname.empty() && hostname.back() == '.') {
        hostname.pop_back();
    }
    return hostname;
}

std::optional<std::string> DohClient::reverseLookupV6(const uint8_t addr[16]) {
    std::string ptr = ipv6ToPtr(addr);
    auto answers = query(ptr, "PTR");
    if (!answers || answers->empty()) return std::nullopt;

    std::string hostname = answers->front().data;
    if (!hostname.empty() && hostname.back() == '.') {
        hostname.pop_back();
    }
    return hostname;
}

} // namespace aifw
