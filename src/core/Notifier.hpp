// Notifier-grensesnitt: kjernen sier fra om hendelser uten å vite hvem som lytter
// (logg, GUI via named pipe, Windows toast osv.).
#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

#include "Types.hpp"

namespace aifw {

enum class EventType { Blocked, WouldBlock, AiError, AiRecovered, Info };
std::string_view toString(EventType t) noexcept;

struct FirewallEvent {
    EventType type{EventType::Info};
    std::chrono::system_clock::time_point time{std::chrono::system_clock::now()};
    std::string flow;      // lesbar 5-tuple
    std::string app;       // UTF-8 sti
    std::string reason;    // "rule:<id>", "ai", "failsafe", ...
    float score{0.0f};     // AI-score hvis relevant
    std::string message;

    [[nodiscard]] nlohmann::json toJson() const;
    static FirewallEvent fromJson(const nlohmann::json& j);
};

class INotifier {
public:
    virtual ~INotifier() = default;
    /// Må være rask og ikke-blokkerende – kalles fra AI-arbeidertråder.
    virtual void notify(const FirewallEvent& ev) = 0;
};

/// Logger hendelser via spdlog.
class LogNotifier final : public INotifier {
public:
    void notify(const FirewallEvent& ev) override;
};

/// Viderefører til flere notifiers. Eier dem (unique_ptr).
class CompositeNotifier final : public INotifier {
public:
    void add(std::unique_ptr<INotifier> n);
    void notify(const FirewallEvent& ev) override;

private:
    std::mutex mutex_;
    std::vector<std::unique_ptr<INotifier>> children_;
};

/// Samler hendelser i minnet (brukes i tester og for "siste hendelser" i GUI).
class MemoryNotifier final : public INotifier {
public:
    explicit MemoryNotifier(std::size_t capacity = 1000) : capacity_(capacity) {}
    void notify(const FirewallEvent& ev) override;
    [[nodiscard]] std::vector<FirewallEvent> events() const;

private:
    std::size_t capacity_;
    mutable std::mutex mutex_;
    std::vector<FirewallEvent> events_;
};

}  // namespace aifw
