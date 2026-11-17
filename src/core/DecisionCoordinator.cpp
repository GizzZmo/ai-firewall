#include "DecisionCoordinator.hpp"

#include <optional>
#include <thread>

#include <spdlog/spdlog.h>

#include "FeatureExtractor.hpp"

namespace aifw {

std::string_view toString(DecisionSource s) noexcept {
    switch (s) {
        case DecisionSource::Rule: return "rule";
        case DecisionSource::Cache: return "cache";
        case DecisionSource::Default: return "default";
        case DecisionSource::AiPending: return "ai_pending";
        case DecisionSource::FailSafe: return "failsafe";
        case DecisionSource::Learning: return "learning";
        case DecisionSource::Host: return "host";
        default: return "invalid";
    }
}

DecisionCoordinator::DecisionCoordinator(const Config& cfg, RuleEngine& rules, FlowTracker& flows, HostTracker& hosts,
                                         VerdictCache& cache, AIDecisionEngine* ai, LearningMode& learning,
                                         INotifier& notifier, IPersistentRuleSink* sink, GeoIpLookup* geoip)
    : cfg_(cfg), rules_(rules), flows_(flows), hosts_(hosts), cache_(cache), ai_(ai), learning_(learning),
      notifier_(notifier), sink_(sink), geoip_(geoip) {}

DecisionCoordinator::~DecisionCoordinator() {
    // AI-callbacks refererer til `this`. Eieren skal stoppe AIDecisionEngine først, men
    // vi venter uansett på callbacks som er midt i kjøring.
    while (inFlight_.load() > 0) std::this_thread::yield();
}

bool DecisionCoordinator::markPending(const FlowKey& k) {
    std::lock_guard lock(pendingMutex_);
    return pending_.insert(k).second;
}

void DecisionCoordinator::clearPending(const FlowKey& k) {
    std::lock_guard lock(pendingMutex_);
    pending_.erase(k);
}

void DecisionCoordinator::setLearningMode(bool on) {
    learning_.setEnabled(on);
    spdlog::info("Læringsmodus {}", on ? "PÅ (ingen AI-blokkering)" : "AV (håndhever)");
}

void DecisionCoordinator::enrichEvent(FirewallEvent& ev, const FlowKey& key) const {
    if (geoip_ && geoip_->available()) {
        ev.country = geoip_->country(key.remoteIp);
    }
}

Decision DecisionCoordinator::decide(const PacketInfo& pkt, TimePoint now) {
    packets_.fetch_add(1, std::memory_order_relaxed);
    auto finish = [this](Decision d) {
        (d.verdict == Verdict::Block ? blocked_ : allowed_).fetch_add(1, std::memory_order_relaxed);
        return d;
    };

    const FlowKey key = pkt.flowKey();
    const auto stats = flows_.update(pkt, now);
    MatchContext ctx{key, pkt.direction, stats ? stats->appPath : pkt.appPath};

    if (stats && stats->totalPackets() == 1 && learning_.enabled()) learning_.recordFlow(ctx);

    // 1) Eksplisitte regler vinner alltid – også i læringsmodus.
    if (auto m = rules_.match(ctx)) {
        ruleHits_.fetch_add(1, std::memory_order_relaxed);
        return finish({m->verdict, DecisionSource::Rule, m->ruleId});
    }

    // 2) Cachet verdikt (typisk fra AI). Et cachet Allow hindrer IKKE re-evaluering:
    //    en flyt som så harmløs ut etter 4 pakker kan endre karakter (f.eks. SYN-flom).
    std::optional<Decision> cached;
    if (auto c = cache_.get(key, now)) {
        cacheHits_.fetch_add(1, std::memory_order_relaxed);
        if (c->verdict == Verdict::Block) {
            if (!learning_.enabled()) return finish({Verdict::Block, DecisionSource::Cache, {}});
            cached = Decision{Verdict::Allow, DecisionSource::Learning, {}};
        } else if (c->verdict == Verdict::Allow) {
            cached = Decision{Verdict::Allow, DecisionSource::Cache, {}};
        }
    }

    // Flyttabellen full: vi har ingen statistikk -> fail-safe standard.
    if (!stats) {
        failSafe_.fetch_add(1, std::memory_order_relaxed);
        return finish({cfg_.defaultVerdict, DecisionSource::FailSafe, {}});
    }

    // 3) Vertsnivå-deteksjon (kun på første pakke i ny flyt).
    if (stats->totalPackets() == 1) {
        const bool isSyn = (pkt.protocol == Protocol::TCP) && (pkt.tcpFlags & tcpflags::SYN) &&
                           !(pkt.tcpFlags & tcpflags::ACK);
        if (hosts_.onNewFlow(key, now, isSyn)) {
            hostBlocks_.fetch_add(1, std::memory_order_relaxed);
            FirewallEvent ev;
            ev.type = learning_.enabled() ? EventType::WouldBlock : EventType::Blocked;
            ev.flow = key.toString();
            ev.app = ctx.appPath;
            ev.reason = "host";
            ev.message = learning_.enabled() ? "Vertsnivå-alarm (læringsmodus)" : "Blokkert av vertsnivå-detektor";
            enrichEvent(ev, key);
            notifier_.notify(ev);
            if (!learning_.enabled()) {
                // Cache blokkeringen slik at senere pakker i samme flyt også stoppes.
                cache_.put(key, Verdict::Block, 1.0, now + cfg_.cache.blockTtl);
                if (sink_ && cfg_.wfp.persistAiBlocks) {
                    try {
                        sink_->persistBlock(key, ctx.appPath, "host scan/brute");
                    } catch (const std::exception& e) {
                        spdlog::error("kunne ikke lagre persistent host-blokkering: {}", e.what());
                    }
                }
                return finish({Verdict::Block, DecisionSource::Host, {}});
            }
        }
    }

    // 4) Asynkron AI. Kun når flyten har nok pakker til meningsfulle features, og
    //    re-evaluer med jevne mellomrom for lange flyter.
    if (ai_ && cfg_.ai.enabled) {
        const bool healthy = ai_->healthy();
        if (healthy != aiWasHealthy_.exchange(healthy)) {
            FirewallEvent ev;
            ev.type = healthy ? EventType::AiRecovered : EventType::AiError;
            ev.message = healthy ? "AI-motoren svarer igjen" : "circuit breaker åpen – kun regelmotor";
            notifier_.notify(ev);
        }
        if (!healthy) {
            if (cached) return finish(*cached);
            failSafe_.fetch_add(1, std::memory_order_relaxed);
            return finish({cfg_.defaultVerdict, DecisionSource::FailSafe, {}});
        }
        const auto n = stats->totalPackets();
        const auto minP = std::max<std::uint32_t>(1, cfg_.ai.minPacketsBeforeInference);
        const auto every = std::max<std::uint32_t>(1, cfg_.ai.reevaluateEveryPackets);
        const bool due = n == minP || (n > minP && (n - minP) % every == 0);
        if (due && markPending(key)) {
            const auto features = FeatureExtractor::extract(key, *stats);
            inFlight_.fetch_add(1);
            const bool ok = ai_->submit(key, features, [this, ctx](const InferenceResult& r) {
                onInference(r, ctx);
                inFlight_.fetch_sub(1);
            });
            if (ok) {
                aiSubmitted_.fetch_add(1, std::memory_order_relaxed);
                if (cached) return finish(*cached);
                return finish({cfg_.defaultVerdict, DecisionSource::AiPending, {}});
            }
            inFlight_.fetch_sub(1);
            clearPending(key);
            if (cached) return finish(*cached);
            failSafe_.fetch_add(1, std::memory_order_relaxed);
            return finish({cfg_.defaultVerdict, DecisionSource::FailSafe, {}});
        }
    }
    if (cached) return finish(*cached);
    return finish({cfg_.defaultVerdict, DecisionSource::Default, {}});
}

void DecisionCoordinator::onInference(const InferenceResult& r, const MatchContext& ctx) {
    clearPending(r.key);
    if (!r.ok) {
        // Fail-safe: ingen cache-oppføring; neste pakke går via regler/standard.
        return;
    }
    const auto now = Clock::now();
    if (r.verdict == Verdict::Block) {
        // I læringsmodus re-evalueres flyter som allerede er flagget; tell/varsle kun én gang per flyt.
        const auto prev = cache_.get(r.key, now);
        const bool alreadyFlagged = prev && prev->verdict == Verdict::Block;
        cache_.put(r.key, Verdict::Block, r.score, now + cfg_.cache.blockTtl);
        if (alreadyFlagged) return;
        FirewallEvent ev;
        ev.flow = r.key.toString();
        ev.app = ctx.appPath;
        ev.reason = "ai";
        ev.score = r.score;
        if (learning_.enabled()) {
            wouldBlock_.fetch_add(1, std::memory_order_relaxed);
            learning_.recordAiVerdict(ctx, r.score);
            ev.type = EventType::WouldBlock;
            ev.message = "AI ville blokkert (læringsmodus)";
        } else {
            ev.type = EventType::Blocked;
            ev.message = "Blokkert av AI";
            if (sink_ && cfg_.wfp.persistAiBlocks) {
                try {
                    sink_->persistBlock(r.key, ctx.appPath, "ai score " + std::to_string(r.score));
                } catch (const std::exception& e) {
                    spdlog::error("kunne ikke lagre persistent blokkering: {}", e.what());
                }
            }
        }
        enrichEvent(ev, r.key);
        notifier_.notify(ev);
    } else if (r.verdict == Verdict::Allow) {
        cache_.put(r.key, Verdict::Allow, r.score, now + cfg_.cache.allowTtl);
    }
    // Unknown (gråsone): ikke cache; ny vurdering ved neste re-evaluering.
}

CoordinatorStats DecisionCoordinator::stats() const noexcept {
    return {packets_.load(), allowed_.load(),     blocked_.load(),  ruleHits_.load(),
            cacheHits_.load(), aiSubmitted_.load(), failSafe_.load(), wouldBlock_.load(), hostBlocks_.load()};
}

}  // namespace aifw
