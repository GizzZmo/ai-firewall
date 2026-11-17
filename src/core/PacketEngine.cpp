#ifdef _WIN32
#include "PacketEngine.hpp"

#include <windivert.h>

#include <cstring>
#include <span>
#include <stdexcept>

#include <spdlog/spdlog.h>

#include "FeatureExtractor.hpp"
#include "ProcessResolver.hpp"
#include "WinUtil.hpp"

namespace aifw {

namespace {
// Stor nok for største mulige pakke per batch-element.
constexpr std::size_t kMaxPacket = WINDIVERT_MTU_MAX;

/// Lengde på første IP-pakke i bufferen, 0 hvis ugyldig.
UINT ipPacketLength(const std::uint8_t* p, UINT avail) noexcept {
    if (avail < 1) return 0;
    const unsigned v = p[0] >> 4;
    UINT len = 0;
    if (v == 4 && avail >= 20) len = static_cast<UINT>((p[2] << 8) | p[3]);
    else if (v == 6 && avail >= 40) len = 40u + static_cast<UINT>((p[4] << 8) | p[5]);
    return (len > 0 && len <= avail) ? len : 0;
}

// Enkel TCP RST for IPv4 (kan utvides for IPv6).
struct TcpRstPacket {
    WINDIVERT_IPHDR ip;
    WINDIVERT_TCPHDR tcp;
};

void sendTcpRst(HANDLE handle, const PacketInfo& info, const WINDIVERT_ADDRESS& origAddr) {
    if (info.srcIp.version != 4) return;  // kun IPv4 for enkelhets skyld nå
    TcpRstPacket rst{};
    rst.ip.Version = 4;
    rst.ip.HdrLength = 5;
    rst.ip.Length = htons(sizeof(rst));
    rst.ip.TTL = 64;
    rst.ip.Protocol = IPPROTO_TCP;
    // Bytt retning: RST tilbake til avsender
    std::memcpy(&rst.ip.SrcAddr, info.dstIp.bytes.data(), 4);
    std::memcpy(&rst.ip.DstAddr, info.srcIp.bytes.data(), 4);
    rst.tcp.SrcPort = htons(info.dstPort);
    rst.tcp.DstPort = htons(info.srcPort);
    rst.tcp.Rst = 1;
    rst.tcp.Ack = 1;
    rst.tcp.HdrLength = 5;
    // Seq/Ack kan settes mer nøyaktig hvis vi har dem, men dette er nok for å avbryte.

    WINDIVERT_ADDRESS addr = origAddr;
    addr.Outbound = !origAddr.Outbound;  // motsatt retning
    WinDivertHelperCalcChecksums(&rst, sizeof(rst), &addr, 0);
    WinDivertSend(handle, &rst, sizeof(rst), nullptr, &addr);
}

// ICMP port unreachable for UDP (IPv4).
struct IcmpUnreachPacket {
    WINDIVERT_IPHDR ip;
    WINDIVERT_ICMPHDR icmp;
    // Original header + 8 bytes payload (forenklet)
    std::uint8_t orig[28];
};

void sendIcmpUnreach(HANDLE handle, const PacketInfo& info, const WINDIVERT_ADDRESS& origAddr) {
    if (info.srcIp.version != 4) return;
    IcmpUnreachPacket icmp{};
    icmp.ip.Version = 4;
    icmp.ip.HdrLength = 5;
    icmp.ip.Length = htons(sizeof(icmp));
    icmp.ip.TTL = 64;
    icmp.ip.Protocol = IPPROTO_ICMP;
    std::memcpy(&icmp.ip.SrcAddr, info.dstIp.bytes.data(), 4);
    std::memcpy(&icmp.ip.DstAddr, info.srcIp.bytes.data(), 4);
    icmp.icmp.Type = 3;  // Destination unreachable
    icmp.icmp.Code = 3;  // Port unreachable
    // Kopier litt av original (forenklet)
    // ... (kan utvides)

    WINDIVERT_ADDRESS addr = origAddr;
    addr.Outbound = !origAddr.Outbound;
    WinDivertHelperCalcChecksums(&icmp, sizeof(icmp), &addr, 0);
    WinDivertSend(handle, &icmp, sizeof(icmp), nullptr, &addr);
}
}  // namespace

PacketEngine::PacketEngine(WinDivertConfig cfg, Decider decider, ProcessResolver* resolver)
    : cfg_(std::move(cfg)), decider_(std::move(decider)), resolver_(resolver), handle_(INVALID_HANDLE_VALUE) {
    if (!decider_) throw std::invalid_argument("PacketEngine krever en decider");
}

PacketEngine::~PacketEngine() { stop(); }

bool PacketEngine::validateFilter(const std::string& filter, std::string& error) {
    const char* errStr = nullptr;
    UINT errPos = 0;
    if (WinDivertHelperCompileFilter(filter.c_str(), WINDIVERT_LAYER_NETWORK, nullptr, 0, &errStr, &errPos)) return true;
    error = std::string(errStr ? errStr : "ukjent feil") + " ved posisjon " + std::to_string(errPos);
    return false;
}

void PacketEngine::start() {
    if (running_) return;
    std::string err;
    if (!validateFilter(cfg_.filter, err)) throw std::runtime_error("ugyldig WinDivert-filter '" + cfg_.filter + "': " + err);

    handle_ = WinDivertOpen(cfg_.filter.c_str(), WINDIVERT_LAYER_NETWORK, cfg_.priority, 0);
    if (handle_ == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        std::string hint;
        if (e == ERROR_ACCESS_DENIED) hint = " – kjør som administrator";
        else if (e == ERROR_FILE_NOT_FOUND) hint = " – WinDivert64.sys mangler ved siden av WinDivert.dll";
        else if (e == ERROR_INVALID_IMAGE_HASH) hint = " – driversignatur avvist (Secure Boot/HVCI? se README)";
        else if (e == ERROR_DRIVER_BLOCKED) hint = " – driveren er blokkert av sikkerhetsprogramvare";
        win::throwLastError("WinDivertOpen" + hint, e);
    }

    WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_LENGTH, cfg_.queueLength);
    WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_TIME, cfg_.queueTimeMs);
    WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_SIZE, cfg_.queueSizeBytes);

    running_ = true;
    for (unsigned i = 0; i < cfg_.workerThreads; ++i)
        workers_.emplace_back([this, i](std::stop_token st) { workerLoop(st, i); });
    spdlog::info("PacketEngine startet: filter='{}', tråder={}, batch={}, reject={}", cfg_.filter, cfg_.workerThreads,
                 cfg_.batchSize, cfg_.injectRejectOnBlock);
}

void PacketEngine::stop() {
    if (!running_.exchange(false) && handle_ == INVALID_HANDLE_VALUE) return;
    if (handle_ != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_RECV);
    }
    for (auto& w : workers_) w.request_stop();
    for (auto& w : workers_)
        if (w.joinable()) w.join();
    workers_.clear();
    if (handle_ != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
    const auto s = stats();
    spdlog::info("PacketEngine stoppet: mottatt={}, reinjisert={}, droppet={}, parsefeil={}", s.received, s.reinjected,
                 s.dropped, s.parseErrors);
}

void PacketEngine::workerLoop(std::stop_token st, unsigned index) {
    const std::size_t batch = cfg_.batchSize;
    std::vector<std::uint8_t> recvBuf(batch * kMaxPacket);
    std::vector<WINDIVERT_ADDRESS> recvAddr(batch);
    std::vector<std::uint8_t> sendBuf(batch * kMaxPacket);
    std::vector<WINDIVERT_ADDRESS> sendAddr(batch);

    spdlog::debug("PacketEngine-tråd {} kjører", index);
    while (!st.stop_requested()) {
        UINT recvLen = 0;
        UINT addrLen = static_cast<UINT>(recvAddr.size() * sizeof(WINDIVERT_ADDRESS));
        if (!WinDivertRecvEx(handle_, recvBuf.data(), static_cast<UINT>(recvBuf.size()), &recvLen, 0, recvAddr.data(),
                             &addrLen, nullptr)) {
            const DWORD e = GetLastError();
            if (e == ERROR_NO_DATA || e == ERROR_INVALID_HANDLE || e == ERROR_OPERATION_ABORTED) break;
            if (e == ERROR_INSUFFICIENT_BUFFER) {
                parseErrors_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            spdlog::error("WinDivertRecvEx feilet: {}", win::lastErrorMessage(e));
            continue;
        }
        batches_.fetch_add(1, std::memory_order_relaxed);
        const UINT nAddr = addrLen / sizeof(WINDIVERT_ADDRESS);

        const std::uint8_t* cur = recvBuf.data();
        UINT remaining = recvLen;
        std::size_t sendLen = 0;
        UINT sendCount = 0;
        for (UINT i = 0; i < nAddr && remaining > 0; ++i) {
            const UINT pktLen = ipPacketLength(cur, remaining);
            if (pktLen == 0) {
                parseErrors_.fetch_add(1, std::memory_order_relaxed);
                break;
            }
            const WINDIVERT_ADDRESS& addr = recvAddr[i];
            received_.fetch_add(1, std::memory_order_relaxed);

            const Direction dir = addr.Outbound ? Direction::Outbound : Direction::Inbound;
            auto info = FeatureExtractor::parseWinDivert(std::span(cur, pktLen), dir);

            bool allow = true;
            if (info) {
                if (resolver_) {
                    if (auto p = resolver_->lookup(info->flowKey())) {
                        info->processId = p->pid;
                        info->appPath = std::move(p->path);
                    }
                }
                try {
                    allow = decider_(*info).verdict != Verdict::Block;
                } catch (const std::exception& e) {
                    spdlog::error("decide() kastet: {} – slipper pakken gjennom", e.what());
                }
            } else {
                parseErrors_.fetch_add(1, std::memory_order_relaxed);
            }

            if (allow) {
                std::memcpy(sendBuf.data() + sendLen, cur, pktLen);
                sendAddr[sendCount++] = addr;
                sendLen += pktLen;
            } else {
                dropped_.fetch_add(1, std::memory_order_relaxed);
                if (cfg_.injectRejectOnBlock && info) {
                    if (info->protocol == Protocol::TCP) {
                        sendTcpRst(handle_, *info, addr);
                    } else if (info->protocol == Protocol::UDP) {
                        sendIcmpUnreach(handle_, *info, addr);
                    }
                }
            }
            cur += pktLen;
            remaining -= pktLen;
        }

        if (sendCount > 0) {
            UINT sent = 0;
            if (!WinDivertSendEx(handle_, sendBuf.data(), static_cast<UINT>(sendLen), &sent, 0, sendAddr.data(),
                                 sendCount * static_cast<UINT>(sizeof(WINDIVERT_ADDRESS)), nullptr)) {
                sendErrors_.fetch_add(1, std::memory_order_relaxed);
                spdlog::warn("WinDivertSendEx feilet: {}", win::lastErrorMessage());
            } else {
                reinjected_.fetch_add(sendCount, std::memory_order_relaxed);
            }
        }
    }
    spdlog::debug("PacketEngine-tråd {} avsluttet", index);
}

PacketEngineStats PacketEngine::stats() const noexcept {
    return {received_.load(), reinjected_.load(), dropped_.load(), parseErrors_.load(), sendErrors_.load(), batches_.load()};
}

}  // namespace aifw
#endif  // _WIN32
