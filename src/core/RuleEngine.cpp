#include "RuleEngine.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <mutex>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace aifw {
namespace {

using nlohmann::json;

char lower(char c) noexcept { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }

Verdict parseAction(const std::string& s) {
    if (s == "allow") return Verdict::Allow;
    if (s == "deny" || s == "block") return Verdict::Block;
    throw std::runtime_error("ugyldig action: '" + s + "' (forventet allow/deny)");
}

Direction parseDirection(const std::string& s) {
    if (s == "in" || s == "inbound") return Direction::Inbound;
    if (s == "out" || s == "outbound") return Direction::Outbound;
    if (s == "any" || s.empty()) return Direction::Any;
    throw std::runtime_error("ugyldig direction: '" + s + "'");
}

Protocol parseProtocol(const std::string& s) {
    if (s == "tcp") return Protocol::TCP;
    if (s == "udp") return Protocol::UDP;
    if (s == "icmp") return Protocol::ICMP;
    if (s == "icmpv6") return Protocol::ICMPv6;
    if (s == "any" || s.empty()) return Protocol::Any;
    throw std::runtime_error("ugyldig protocol: '" + s + "'");
}

std::uint16_t parsePort(std::string_view s) {
    unsigned v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size() || v > 65535) throw std::runtime_error("ugyldig port: '" + std::string(s) + "'");
    return static_cast<std::uint16_t>(v);
}

std::vector<PortRange> parsePorts(const json& arr) {
    std::vector<PortRange> out;
    if (arr.is_null()) return out;
    if (!arr.is_array()) throw std::runtime_error("porter må være en liste");
    for (const auto& e : arr) {
        if (e.is_number_unsigned()) {
            const auto v = e.get<unsigned>();
            if (v > 65535) throw std::runtime_error("port utenfor område");
            out.push_back({static_cast<std::uint16_t>(v), static_cast<std::uint16_t>(v)});
        } else if (e.is_string()) {
            const auto s = e.get<std::string>();
            const auto dash = s.find('-');
            if (dash == std::string::npos) {
                const auto p = parsePort(s);
                out.push_back({p, p});
            } else {
                PortRange r{parsePort(std::string_view(s).substr(0, dash)), parsePort(std::string_view(s).substr(dash + 1))};
                if (r.first > r.last) throw std::runtime_error("portområde baklengs: '" + s + "'");
                out.push_back(r);
            }
        } else {
            throw std::runtime_error("port må være tall eller \"a-b\"-streng");
        }
    }
    return out;
}

json portsToJson(const std::vector<PortRange>& v) {
    json arr = json::array();
    for (const auto& r : v) {
        if (r.first == r.last) arr.push_back(r.first);
        else arr.push_back(std::to_string(r.first) + "-" + std::to_string(r.last));
    }
    return arr;
}

std::string cidrToString(const Cidr& c) { return c.network.toString() + "/" + std::to_string(c.prefix); }

bool anyRange(const std::vector<PortRange>& v, std::uint16_t p) noexcept {
    return v.empty() || std::any_of(v.begin(), v.end(), [p](const PortRange& r) { return r.contains(p); });
}

}  // namespace

bool RuleEngine::wildcardMatch(std::string_view pat, std::string_view txt) noexcept {
    // Iterativ glob-matching med backtracking til siste '*': O(n*m) verste fall, ingen rekursjon.
    std::size_t p = 0, t = 0, star = std::string_view::npos, mark = 0;
    while (t < txt.size()) {
        if (p < pat.size() && (pat[p] == '?' || lower(pat[p]) == lower(txt[t]))) {
            ++p; ++t;
        } else if (p < pat.size() && pat[p] == '*') {
            star = p++;
            mark = t;
        } else if (star != std::string_view::npos) {
            p = star + 1;
            t = ++mark;
        } else {
            return false;
        }
    }
    while (p < pat.size() && pat[p] == '*') ++p;
    return p == pat.size();
}

bool RuleEngine::appMatches(const std::string& pattern, const std::string& appPath) noexcept {
    if (pattern.empty()) return true;
    if (appPath.empty()) return false;
    const bool hasSep = pattern.find_first_of("\\/") != std::string::npos;
    if (hasSep) return wildcardMatch(pattern, appPath);
    // Kun filnavn: sammenlign mot siste komponent av stien.
    const auto pos = appPath.find_last_of("\\/");
    const std::string_view file = pos == std::string::npos ? std::string_view(appPath) : std::string_view(appPath).substr(pos + 1);
    return wildcardMatch(pattern, file);
}

Rule RuleEngine::ruleFromJson(const json& j) {
    Rule r;
    r.id = j.at("id").get<std::string>();
    if (r.id.empty()) throw std::runtime_error("regel mangler id");
    try {
        r.action = parseAction(j.at("action").get<std::string>());
        r.direction = parseDirection(j.value("direction", std::string("any")));
        r.protocol = parseProtocol(j.value("protocol", std::string("any")));
        if (j.contains("remote_ips")) {
            for (const auto& ip : j.at("remote_ips")) {
                const auto s = ip.get<std::string>();
                if (s == "any" || s == "*") { r.remoteIps.clear(); break; }
                auto c = Cidr::parse(s);
                if (!c) throw std::runtime_error("ugyldig IP/CIDR: '" + s + "'");
                r.remoteIps.push_back(*c);
            }
        }
        r.remotePorts = parsePorts(j.value("remote_ports", json()));
        r.localPorts = parsePorts(j.value("local_ports", json()));
        r.app = j.value("app", std::string());
        r.priority = j.value("priority", 0);
        r.enabled = j.value("enabled", true);
        r.persistent = j.value("persistent", false);
        r.comment = j.value("comment", std::string());
        r.source = j.value("source", std::string("user"));
    } catch (const json::exception& e) {
        throw std::runtime_error("regel '" + r.id + "': " + e.what());
    } catch (const std::runtime_error& e) {
        throw std::runtime_error("regel '" + r.id + "': " + e.what());
    }
    return r;
}

json RuleEngine::ruleToJson(const Rule& r) {
    json j;
    j["id"] = r.id;
    j["action"] = r.action == Verdict::Allow ? "allow" : "deny";
    j["direction"] = std::string(toString(r.direction));
    j["protocol"] = std::string(toString(r.protocol));
    json ips = json::array();
    for (const auto& c : r.remoteIps) ips.push_back(cidrToString(c));
    j["remote_ips"] = ips;
    j["remote_ports"] = portsToJson(r.remotePorts);
    j["local_ports"] = portsToJson(r.localPorts);
    if (!r.app.empty()) j["app"] = r.app;
    j["priority"] = r.priority;
    j["enabled"] = r.enabled;
    j["persistent"] = r.persistent;
    if (!r.comment.empty()) j["comment"] = r.comment;
    j["source"] = r.source;
    return j;
}

void RuleEngine::loadFromJson(const json& doc) {
    if (!doc.contains("rules") || !doc["rules"].is_array()) throw std::runtime_error("rules.json: mangler 'rules'-liste");
    std::vector<Rule> parsed;
    for (const auto& j : doc["rules"]) parsed.push_back(ruleFromJson(j));
    // Sjekk duplikate id-er før vi bytter ut regelsettet (alt-eller-ingenting).
    std::vector<std::string> ids;
    for (const auto& r : parsed) ids.push_back(r.id);
    std::sort(ids.begin(), ids.end());
    if (auto dup = std::adjacent_find(ids.begin(), ids.end()); dup != ids.end())
        throw std::runtime_error("duplikat regel-id: '" + *dup + "'");
    std::unique_lock lock(mutex_);
    rules_ = std::move(parsed);
    sortLocked();
}

void RuleEngine::loadFromFile(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("kan ikke åpne regelfil: " + path.string());
    loadFromJson(json::parse(in, nullptr, true, /*ignore_comments=*/true));
}

void RuleEngine::saveToFile(const std::filesystem::path& path) const {
    // Skriv til midlertidig fil og bytt atomisk, så en krasj ikke etterlater halvskrevet regelfil.
    const auto tmp = std::filesystem::path(path).concat(".tmp");
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) throw std::runtime_error("kan ikke skrive regelfil: " + tmp.string());
        out << toJson().dump(2) << '\n';
    }
    std::filesystem::rename(tmp, path);
}

json RuleEngine::toJson() const {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    for (const auto& r : rules_) arr.push_back(ruleToJson(r));
    return json{{"version", 1}, {"rules", arr}};
}

void RuleEngine::addRule(Rule rule) {
    std::unique_lock lock(mutex_);
    std::erase_if(rules_, [&](const Rule& r) { return r.id == rule.id; });
    rules_.push_back(std::move(rule));
    sortLocked();
}

bool RuleEngine::removeRule(const std::string& id) {
    std::unique_lock lock(mutex_);
    return std::erase_if(rules_, [&](const Rule& r) { return r.id == id; }) > 0;
}

std::vector<Rule> RuleEngine::rules() const {
    std::shared_lock lock(mutex_);
    return rules_;
}

std::size_t RuleEngine::size() const {
    std::shared_lock lock(mutex_);
    return rules_.size();
}

void RuleEngine::sortLocked() {
    std::stable_sort(rules_.begin(), rules_.end(), [](const Rule& a, const Rule& b) {
        if (a.priority != b.priority) return a.priority > b.priority;
        return a.action == Verdict::Block && b.action != Verdict::Block;  // deny først ved lik prioritet
    });
}

bool RuleEngine::matches(const Rule& r, const MatchContext& c) noexcept {
    if (!r.enabled) return false;
    if (r.direction != Direction::Any && r.direction != c.direction) return false;
    if (r.protocol != Protocol::Any && r.protocol != c.key.protocol) return false;
    if (!anyRange(r.remotePorts, c.key.remotePort)) return false;
    if (!anyRange(r.localPorts, c.key.localPort)) return false;
    if (!r.remoteIps.empty() &&
        std::none_of(r.remoteIps.begin(), r.remoteIps.end(), [&](const Cidr& n) { return n.contains(c.key.remoteIp); }))
        return false;
    return appMatches(r.app, c.appPath);
}

std::optional<RuleMatch> RuleEngine::match(const MatchContext& ctx) const {
    std::shared_lock lock(mutex_);
    for (const auto& r : rules_)
        if (matches(r, ctx)) return RuleMatch{r.action, r.id};
    return std::nullopt;
}

}  // namespace aifw
