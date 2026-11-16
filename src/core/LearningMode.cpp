#include "LearningMode.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>

#include <nlohmann/json.hpp>

namespace aifw {
using nlohmann::json;

namespace {
ObservationKey keyOf(const MatchContext& c) {
    // Inngående: lokal port er det interessante (tjenesten som lytter).
    const std::uint16_t port = c.direction == Direction::Inbound ? c.key.localPort : c.key.remotePort;
    return {c.appPath, c.direction, c.key.protocol, port};
}

std::string sanitizeId(std::string s) {
    for (auto& ch : s)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '-' && ch != '.') ch = '_';
    return s;
}
}  // namespace

Observation& LearningMode::slot(const MatchContext& ctx) {
    const auto k = keyOf(ctx);
    auto it = obs_.find(k);
    if (it != obs_.end()) return it->second;
    if (obs_.size() >= kMaxObservations) {
        overflow_ = {};
        return overflow_;
    }
    return obs_[k];
}

void LearningMode::recordFlow(const MatchContext& ctx) {
    std::lock_guard lock(mutex_);
    auto& o = slot(ctx);
    ++o.flows;
    if (o.remoteIps.size() < kMaxIpsPerObservation) o.remoteIps.insert(ctx.key.remoteIp.toString());
}

void LearningMode::recordAiVerdict(const MatchContext& ctx, float score) {
    std::lock_guard lock(mutex_);
    auto& o = slot(ctx);
    ++o.aiFlagged;
    o.maxScore = std::max(o.maxScore, score);
}

std::vector<Rule> LearningMode::suggestRules(std::uint64_t minFlows, std::uint64_t minAiFlags) const {
    std::lock_guard lock(mutex_);
    std::vector<Rule> out;
    for (const auto& [k, o] : obs_) {
        Rule r;
        r.direction = k.direction;
        r.protocol = k.protocol;
        r.app = k.app;
        r.source = "learning";
        const PortRange port{k.remotePort, k.remotePort};
        if (k.direction == Direction::Inbound) r.localPorts = {port};
        else r.remotePorts = {port};
        const std::string base = sanitizeId(std::string(toString(k.direction)) + "-" + std::string(toString(k.protocol)) +
                                            "-" + std::to_string(k.remotePort) + "-" +
                                            (k.app.empty() ? std::string("anyapp") : k.app.substr(k.app.find_last_of("\\/") + 1)));
        if (o.aiFlagged >= minAiFlags) {
            r.id = "learn-deny-" + base;
            r.action = Verdict::Block;
            r.priority = 50;
            r.comment = "AI flagget " + std::to_string(o.aiFlagged) + " av " + std::to_string(o.flows) + " flyter (maks score " +
                        std::to_string(o.maxScore).substr(0, 4) + ")";
            out.push_back(std::move(r));
        } else if (o.flows >= minFlows && o.aiFlagged == 0) {
            r.id = "learn-allow-" + base;
            r.action = Verdict::Allow;
            r.priority = 10;
            r.comment = "Observert " + std::to_string(o.flows) + " flyter i læringsmodus";
            out.push_back(std::move(r));
        }
    }
    return out;
}

std::map<ObservationKey, Observation> LearningMode::snapshot() const {
    std::lock_guard lock(mutex_);
    return obs_;
}

json LearningMode::toJson() const {
    std::lock_guard lock(mutex_);
    json arr = json::array();
    for (const auto& [k, o] : obs_) {
        arr.push_back({{"app", k.app}, {"direction", std::string(toString(k.direction))},
                       {"protocol", std::string(toString(k.protocol))}, {"port", k.remotePort}, {"flows", o.flows},
                       {"ai_flagged", o.aiFlagged}, {"max_score", o.maxScore}, {"remote_ips", o.remoteIps}});
    }
    return json{{"version", 1}, {"observations", arr}};
}

void LearningMode::loadJson(const json& j) {
    std::map<ObservationKey, Observation> fresh;
    for (const auto& e : j.at("observations")) {
        ObservationKey k;
        k.app = e.value("app", std::string());
        const auto d = e.value("direction", std::string("out"));
        k.direction = d == "in" ? Direction::Inbound : (d == "out" ? Direction::Outbound : Direction::Any);
        const auto p = e.value("protocol", std::string("any"));
        k.protocol = p == "tcp" ? Protocol::TCP : p == "udp" ? Protocol::UDP : p == "icmp" ? Protocol::ICMP
                   : p == "icmpv6" ? Protocol::ICMPv6 : Protocol::Any;
        k.remotePort = e.value("port", std::uint16_t{0});
        Observation o;
        o.flows = e.value("flows", std::uint64_t{0});
        o.aiFlagged = e.value("ai_flagged", std::uint64_t{0});
        o.maxScore = e.value("max_score", 0.0f);
        if (e.contains("remote_ips")) o.remoteIps = e["remote_ips"].get<std::set<std::string>>();
        fresh[k] = std::move(o);
    }
    std::lock_guard lock(mutex_);
    obs_ = std::move(fresh);
}

void LearningMode::save(const std::filesystem::path& path) const {
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
    const auto tmp = std::filesystem::path(path).concat(".tmp");
    {
        std::ofstream out(tmp, std::ios::trunc);
        out << toJson().dump(2) << '\n';
    }
    std::filesystem::rename(tmp, path);
}

void LearningMode::load(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) return;  // ingen tidligere data er ok
    loadJson(json::parse(in));
}

void LearningMode::clear() {
    std::lock_guard lock(mutex_);
    obs_.clear();
}

}  // namespace aifw
