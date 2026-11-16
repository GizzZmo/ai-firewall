// aifw_sim – plattformuavhengig trafikk-simulator.
// Bygger syntetiske rå IP-pakker (vanlig surfing, portskanning, SYN-flom, høy-entropi
// UDP-exfiltrering), kjører dem gjennom samme FeatureExtractor -> FlowTracker ->
// DecisionCoordinator-kjede som Windows-tjenesten, og skriver ut statistikk.
// Nyttig for å teste regler, terskler og modeller uten WinDivert/administrator.
//
//   aifw_sim [--config config/config.json] [--base <dir>] [--learning] [--seed N]
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "FeatureExtractor.hpp"
#include "FirewallCore.hpp"
#include "Log.hpp"

using namespace aifw;
using namespace std::chrono_literals;

namespace {

std::vector<std::uint8_t> buildIpv4(std::uint32_t src, std::uint32_t dst, Protocol proto, std::uint16_t sp,
                                    std::uint16_t dp, std::uint8_t flags, const std::vector<std::uint8_t>& payload) {
    const std::size_t l4len = proto == Protocol::TCP ? 20 : 8;
    std::vector<std::uint8_t> p(20 + l4len + payload.size(), 0);
    auto put16 = [&](std::size_t o, std::uint16_t v) { p[o] = static_cast<std::uint8_t>(v >> 8); p[o + 1] = static_cast<std::uint8_t>(v); };
    auto put32 = [&](std::size_t o, std::uint32_t v) { for (int i = 0; i < 4; ++i) p[o + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (24 - 8 * i)); };
    p[0] = 0x45;
    put16(2, static_cast<std::uint16_t>(p.size()));
    p[8] = 64;
    p[9] = static_cast<std::uint8_t>(proto);
    put32(12, src);
    put32(16, dst);
    put16(20, sp);
    put16(22, dp);
    if (proto == Protocol::TCP) {
        p[32] = 5 << 4;
        p[33] = flags;
    } else {
        put16(24, static_cast<std::uint16_t>(8 + payload.size()));
    }
    std::copy(payload.begin(), payload.end(), p.begin() + static_cast<long>(20 + l4len));
    return p;
}

struct Sim {
    FirewallCore& core;
    std::mt19937 rng;
    TimePoint t = Clock::now();
    std::uint64_t blocked = 0, total = 0;
    const std::uint32_t local = 0xC0A8010A;  // 192.168.1.10

    Decision send(std::uint32_t remote, Protocol proto, std::uint16_t lport, std::uint16_t rport, std::uint8_t flags,
                  std::size_t payloadLen, bool random, Direction dir, std::chrono::microseconds gap, const char* app) {
        std::vector<std::uint8_t> payload(payloadLen);
        for (auto& b : payload) b = random ? static_cast<std::uint8_t>(rng()) : static_cast<std::uint8_t>("GET / HTTP/1.1 "[rng() % 15]);
        auto raw = dir == Direction::Outbound ? buildIpv4(local, remote, proto, lport, rport, flags, payload)
                                              : buildIpv4(remote, local, proto, rport, lport, flags, payload);
        auto pkt = FeatureExtractor::parse(raw, dir);
        if (!pkt) throw std::runtime_error("intern feil: kunne ikke parse simulert pakke");
        pkt->appPath = app;
        t += gap;
        auto d = core.decide(*pkt, t);
        ++total;
        if (d.verdict == Verdict::Block) ++blocked;
        return d;
    }
};

void report(const char* name, std::uint64_t blocked, std::uint64_t total) {
    std::printf("  %-34s %6llu / %-6llu pakker blokkert\n", name, static_cast<unsigned long long>(blocked),
                static_cast<unsigned long long>(total));
}

}  // namespace

int main(int argc, char** argv) {
    std::filesystem::path base = std::filesystem::current_path();
    std::string configPath = "config/config.json";
    bool learning = false;
    unsigned seed = 1;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) configPath = argv[++i];
        else if (a == "--base" && i + 1 < argc) base = argv[++i];
        else if (a == "--learning") learning = true;
        else if (a == "--seed" && i + 1 < argc) seed = static_cast<unsigned>(std::stoul(argv[++i]));
        else {
            std::cerr << "bruk: aifw_sim [--config fil] [--base mappe] [--learning] [--seed N]\n";
            return 2;
        }
    }
    try {
        auto cfg = Config::loadFromFile(base / configPath);
        cfg.learningMode = learning;
        cfg.learningPath = "data/sim_learning.json";
        initLogging("warn", {}, true);
        FirewallCore core(cfg, base);
        Sim sim{core, std::mt19937(seed)};

        std::puts("== AI-Firewall simulator ==");
        std::printf("modell: %s, læringsmodus: %s\n", core.ai() ? core.ai()->modelName().c_str() : "(av)",
                    learning ? "på" : "av");

        // 1) Vanlig HTTPS-surfing: handshake + forespørsel/svar, toveis.
        auto b0 = sim.blocked, n0 = sim.total;
        for (int c = 0; c < 30; ++c) {
            const auto lport = static_cast<std::uint16_t>(50000 + c);
            const std::uint32_t remote = 0x5DB8D800 + static_cast<std::uint32_t>(c);  // 93.184.216.x
            sim.send(remote, Protocol::TCP, lport, 443, tcpflags::SYN, 0, false, Direction::Outbound, 20ms, "C:\\Apps\\browser.exe");
            sim.send(remote, Protocol::TCP, lport, 443, tcpflags::SYN | tcpflags::ACK, 0, false, Direction::Inbound, 15ms, "C:\\Apps\\browser.exe");
            for (int k = 0; k < 20; ++k) {
                sim.send(remote, Protocol::TCP, lport, 443, tcpflags::ACK | tcpflags::PSH, 300, true, Direction::Outbound, 30ms, "C:\\Apps\\browser.exe");
                sim.send(remote, Protocol::TCP, lport, 443, tcpflags::ACK, 1200, true, Direction::Inbound, 25ms, "C:\\Apps\\browser.exe");
            }
        }
        report("vanlig HTTPS-surfing", sim.blocked - b0, sim.total - n0);

        // 2) Portskanning: én SYN per port, ingen svar. Hver port er en ny flyt, så per-flyt
        //    AI ser lite – her er det regler (f.eks. telnet) som slår til. Viser begrensning.
        b0 = sim.blocked; n0 = sim.total;
        for (std::uint16_t port = 1; port <= 1024; ++port)
            sim.send(0x08080808, Protocol::TCP, 40000, port, tcpflags::SYN, 0, false, Direction::Outbound, 1ms, "C:\\Temp\\scan.exe");
        report("portskanning (1 pakke/flyt)", sim.blocked - b0, sim.total - n0);

        // 3) SYN-flom mot én tjeneste: mange SYN i samme flyt uten svar.
        b0 = sim.blocked; n0 = sim.total;
        for (int i = 0; i < 400; ++i)
            sim.send(0x2D21200A, Protocol::TCP, 41000, 80, tcpflags::SYN, 0, false, Direction::Outbound, 100us, "C:\\Temp\\flood.exe");
        std::this_thread::sleep_for(100ms);  // la AI svare; påfølgende pakker treffer cache
        for (int i = 0; i < 400; ++i)
            sim.send(0x2D21200A, Protocol::TCP, 41000, 80, tcpflags::SYN, 0, false, Direction::Outbound, 100us, "C:\\Temp\\flood.exe");
        report("SYN-flom (én flyt)", sim.blocked - b0, sim.total - n0);

        // 4) Høy-entropi UDP-exfiltrering til høy port, kun utgående.
        b0 = sim.blocked; n0 = sim.total;
        for (int i = 0; i < 1500; ++i) {
            sim.send(0x2D21200B, Protocol::UDP, 53000, 51820, 0, 1200, true, Direction::Outbound, 200us, "C:\\Temp\\exfil.exe");
            if (i == 800) std::this_thread::sleep_for(100ms);
        }
        report("UDP-exfiltrering (høy entropi)", sim.blocked - b0, sim.total - n0);

        // 5) Trafikk mot blokkliste (TEST-NET) – regel.
        b0 = sim.blocked; n0 = sim.total;
        for (int i = 0; i < 10; ++i)
            sim.send(0xCB007101, Protocol::TCP, 42000, 443, tcpflags::SYN, 0, false, Direction::Outbound, 1ms, "C:\\Apps\\x.exe");
        report("mot blokkliste 203.0.113.0/24", sim.blocked - b0, sim.total - n0);

        std::this_thread::sleep_for(50ms);
        std::puts("\nStatus:");
        std::puts(core.statusJson().dump(2).c_str());
        if (learning) {
            std::puts("\nForeslåtte regler fra læringsmodus (deny allerede ved 1 AI-flagget flyt, kun for demo):");
            for (const auto& r : core.learning().suggestRules(3, /*minAiFlags=*/1)) std::puts(RuleEngine::ruleToJson(r).dump().c_str());
        }
        core.stop();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "feil: " << e.what() << '\n';
        return 1;
    }
}
