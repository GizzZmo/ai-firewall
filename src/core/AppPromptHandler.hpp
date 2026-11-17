#pragma once
// Håndterer «spør brukeren»-flyt for nye apper.
// Sender IPC-melding til GUI og venter på svar (med timeout).

#include <string>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <chrono>

namespace aifw {

class INotifier;
class AppStats;

struct AppPromptResult {
    bool allowed{false};
    bool remember{false};
    bool timedOut{false};
};

class AppPromptHandler {
public:
    AppPromptHandler(AppStats& stats, INotifier& notifier);

    // Sjekk om vi skal spørre, og send prompt hvis nødvendig.
    // Returnerer umiddelbart; svar kommer via onResponse.
    void maybePrompt(const std::string& appPath);

    // Kalles når GUI svarer (fra IPC-handler).
    void onResponse(const std::string& appPath, bool allowed, bool remember);

    // Registrer callback for å sende IPC-melding.
    void setSendCallback(std::function<void(const std::string& json)> cb);

private:
    AppStats& stats_;
    INotifier& notifier_;
    std::function<void(const std::string&)> sendCb_;

    std::mutex mutex_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> pending_;
};

} // namespace aifw
