#pragma once
// Utvidelser til FirewallEvent for DNS og app-prompt.
// Kan merges inn i Notifier.hpp senere.

#include <string>
#include <optional>

namespace aifw {

// Utvidet hendelse med hostname fra DnsResolver
struct FirewallEventExt {
    std::string remoteHost;          // reverse DNS (tom hvis ukjent)
    std::string remoteIp;            // original IP
    bool dnsLookupPending{false};    // oppslag pågår i bakgrunnen
};

// IPC-melding for «spør brukeren»-dialog
struct AppPromptRequest {
    std::string appPath;
    std::string appName;             // bare filnavn
    std::uint64_t firstSeenMs{0};
    std::string suggestedAction;     // "allow" eller "deny"
};

struct AppPromptResponse {
    std::string appPath;
    bool allowed{false};
    bool remember{true};             // lagre som regel?
};

// Hjelpefunksjon for å lage IPC-melding
inline nlohmann::json makeAppPrompt(const AppPromptRequest& req) {
    return {
        {"type", "app_prompt"},
        {"app", req.appPath},
        {"name", req.appName},
        {"suggested", req.suggestedAction}
    };
}

} // namespace aifw
