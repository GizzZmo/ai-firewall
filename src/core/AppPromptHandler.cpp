#include "AppPromptHandler.hpp"
#include "AppStats.hpp"
#include "Notifier.hpp"
#include "FirewallEventExt.hpp"

#include <nlohmann/json.hpp>

namespace aifw {

AppPromptHandler::AppPromptHandler(AppStats& stats, INotifier& notifier)
    : stats_(stats), notifier_(notifier) {}

void AppPromptHandler::setSendCallback(std::function<void(const std::string&)> cb) {
    sendCb_ = std::move(cb);
}

void AppPromptHandler::maybePrompt(const std::string& appPath) {
    if (appPath.empty()) return;
    if (!stats_.shouldPrompt(appPath)) return;

    {
        std::lock_guard lock(mutex_);
        if (pending_.count(appPath)) return;  // allerede spurt
        pending_[appPath] = std::chrono::steady_clock::now();
    }

    AppPromptRequest req;
    req.appPath = appPath;
    // Trekk ut filnavn
    auto pos = appPath.find_last_of("\\/");
    req.appName = (pos != std::string::npos) ? appPath.substr(pos + 1) : appPath;
    req.suggestedAction = "allow";

    if (sendCb_) {
        auto j = makeAppPrompt(req);
        sendCb_(j.dump());
    }

    // Logg at vi spør
    FirewallEvent ev;
    ev.type = EventType::Info;
    ev.app = appPath;
    ev.message = "Spør brukeren om " + req.appName;
    notifier_.notify(ev);
}

void AppPromptHandler::onResponse(const std::string& appPath, bool allowed, bool remember) {
    {
        std::lock_guard lock(mutex_);
        pending_.erase(appPath);
    }

    stats_.markPrompted(appPath, allowed);

    FirewallEvent ev;
    ev.type = allowed ? EventType::Info : EventType::Blocked;
    ev.app = appPath;
    ev.message = allowed ? "Bruker tillot" : "Bruker blokkerte";
    if (remember) ev.message += " (husket)";
    notifier_.notify(ev);

    // TODO: hvis remember && !allowed → legg til regel via RuleEngine
}

} // namespace aifw
