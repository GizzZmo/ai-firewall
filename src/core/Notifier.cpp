#include "Notifier.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace aifw {

std::string_view toString(EventType t) noexcept {
    switch (t) {
        case EventType::Blocked: return "blocked";
        case EventType::WouldBlock: return "would_block";
        case EventType::AiError: return "ai_error";
        case EventType::AiRecovered: return "ai_recovered";
        default: return "info";
    }
}

nlohmann::json FirewallEvent::toJson() const {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
    return {{"type", std::string(aifw::toString(type))}, {"time_ms", ms}, {"flow", flow}, {"app", app},
            {"reason", reason}, {"score", score}, {"message", message}, {"country", country}};
}

FirewallEvent FirewallEvent::fromJson(const nlohmann::json& j) {
    FirewallEvent e;
    const auto t = j.value("type", std::string("info"));
    if (t == "blocked") e.type = EventType::Blocked;
    else if (t == "would_block") e.type = EventType::WouldBlock;
    else if (t == "ai_error") e.type = EventType::AiError;
    else if (t == "ai_recovered") e.type = EventType::AiRecovered;
    e.time = std::chrono::system_clock::time_point(std::chrono::milliseconds(j.value("time_ms", std::int64_t{0})));
    e.flow = j.value("flow", std::string());
    e.app = j.value("app", std::string());
    e.reason = j.value("reason", std::string());
    e.score = j.value("score", 0.0f);
    e.message = j.value("message", std::string());
    e.country = j.value("country", std::string());
    return e;
}

void LogNotifier::notify(const FirewallEvent& ev) {
    const auto countryPart = ev.country.empty() ? std::string() : " country=" + ev.country;
    switch (ev.type) {
        case EventType::Blocked:
            spdlog::warn("BLOKKERT {} app='{}' grunn={} score={:.3f}{}", ev.flow, ev.app, ev.reason, ev.score, countryPart);
            break;
        case EventType::WouldBlock:
            spdlog::info("[læring] ville blokkert {} app='{}' grunn={} score={:.3f}{}", ev.flow, ev.app, ev.reason, ev.score, countryPart);
            break;
        case EventType::AiError:
            spdlog::error("AI-feil: {} – faller tilbake til regelmotor", ev.message);
            break;
        case EventType::AiRecovered:
            spdlog::info("AI tilgjengelig igjen: {}", ev.message);
            break;
        default:
            spdlog::info("{}", ev.message);
    }
}

void CompositeNotifier::add(std::unique_ptr<INotifier> n) {
    std::lock_guard lock(mutex_);
    children_.push_back(std::move(n));
}

void CompositeNotifier::notify(const FirewallEvent& ev) {
    std::lock_guard lock(mutex_);
    for (auto& c : children_) {
        try {
            c->notify(ev);
        } catch (const std::exception& e) {
            spdlog::error("notifier kastet unntak: {}", e.what());  // én defekt lytter skal ikke stoppe andre
        }
    }
}

void MemoryNotifier::notify(const FirewallEvent& ev) {
    std::lock_guard lock(mutex_);
    if (events_.size() >= capacity_) events_.erase(events_.begin());
    events_.push_back(ev);
}

std::vector<FirewallEvent> MemoryNotifier::events() const {
    std::lock_guard lock(mutex_);
    return events_;
}

}  // namespace aifw
