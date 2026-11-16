// Regelbasert motor: eksplisitte allow/deny-regler lastet fra JSON.
// Dette er både første beslutningslag og fail-safe når AI ikke er tilgjengelig.
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

#include "Types.hpp"

namespace aifw {

struct PortRange {
    std::uint16_t first{0};
    std::uint16_t last{65535};
    [[nodiscard]] bool contains(std::uint16_t p) const noexcept { return p >= first && p <= last; }
    friend bool operator==(const PortRange&, const PortRange&) = default;
};

struct Rule {
    std::string id;
    Verdict action{Verdict::Block};
    Direction direction{Direction::Any};
    Protocol protocol{Protocol::Any};
    std::vector<Cidr> remoteIps;          // tom = alle
    std::vector<PortRange> remotePorts;   // tom = alle
    std::vector<PortRange> localPorts;    // tom = alle
    std::string app;                      // tom = alle. Full sti, filnavn eller wildcard (*, ?) – case-insensitiv
    int priority{0};                      // høyere vinner; ved lik prioritet vinner deny
    bool enabled{true};
    bool persistent{false};               // skal også legges inn i WFP (overlever omstart)
    std::string comment;
    std::string source{"user"};           // "user", "learning", "ai"
};

struct RuleMatch {
    Verdict verdict;
    std::string ruleId;
};

/// Kontekst for matching – alt som trengs fra en pakke/flyt.
struct MatchContext {
    FlowKey key;
    Direction direction{Direction::Outbound};
    std::string appPath;  // UTF-8
};

class RuleEngine {
public:
    RuleEngine() = default;

    /// Laster regler fra JSON (erstatter eksisterende). Kaster std::runtime_error med
    /// beskrivende melding ved ugyldig regel – ingen delvis innlasting.
    void loadFromJson(const nlohmann::json& doc);
    void loadFromFile(const std::filesystem::path& path);
    void saveToFile(const std::filesystem::path& path) const;
    [[nodiscard]] nlohmann::json toJson() const;

    void addRule(Rule rule);              // erstatter regel med samme id
    bool removeRule(const std::string& id);
    [[nodiscard]] std::vector<Rule> rules() const;
    [[nodiscard]] std::size_t size() const;

    /// Første treff etter prioritet. nullopt = ingen regel matcher.
    [[nodiscard]] std::optional<RuleMatch> match(const MatchContext& ctx) const;

    static Rule ruleFromJson(const nlohmann::json& j);
    static nlohmann::json ruleToJson(const Rule& r);
    static bool wildcardMatch(std::string_view pattern, std::string_view text) noexcept;  // case-insensitiv
    static bool appMatches(const std::string& pattern, const std::string& appPath) noexcept;

private:
    void sortLocked();
    static bool matches(const Rule& r, const MatchContext& ctx) noexcept;

    mutable std::shared_mutex mutex_;
    std::vector<Rule> rules_;  // sortert: prioritet synkende, deny før allow
};

}  // namespace aifw
