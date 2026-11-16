// Kobler flyter til prosess-ID og exe-sti ved hjelp av WinDivert sitt FLOW-lag.
//
// NETWORK-laget (der pakkene fanges) har ikke prosess-ID. FLOW-laget sender en hendelse
// (FLOW_ESTABLISHED / FLOW_DELETED) med ProcessId og 5-tuple for hver forbindelse. Vi åpner
// et eget håndtak i SNIFF + RECV_ONLY-modus og bygger en oppslagstabell.
//
// Begrensning: FLOW_ESTABLISHED kommer når ALE har godkjent forbindelsen, så de aller første
// pakkene (f.eks. TCP SYN) kan passere før appen er kjent. For streng per-app-håndhevelse
// fra første pakke: bruk persistente WFP-regler med app-betingelse (WfpManager).
#pragma once
#ifdef _WIN32

#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>

#include "Types.hpp"
#include "WinUtil.hpp"

namespace aifw {

struct ProcessInfo {
    std::uint32_t pid{0};
    std::string path;  // UTF-8
};

class ProcessResolver {
public:
    ProcessResolver();
    ~ProcessResolver();  // stopper tråd og lukker håndtak
    ProcessResolver(const ProcessResolver&) = delete;
    ProcessResolver& operator=(const ProcessResolver&) = delete;

    void start();
    void stop();

    [[nodiscard]] std::optional<ProcessInfo> lookup(const FlowKey& key) const;
    [[nodiscard]] std::size_t size() const;

    /// exe-sti for prosess-ID (cachet). "System" for PID 4, tom ved feil.
    std::string pathForPid(std::uint32_t pid) const;

private:
    void loop(std::stop_token st);

    HANDLE handle_{INVALID_HANDLE_VALUE};
    mutable std::mutex mutex_;
    std::unordered_map<FlowKey, ProcessInfo, FlowKeyHash> flows_;
    mutable std::mutex pidMutex_;
    mutable std::unordered_map<std::uint32_t, std::string> pidPaths_;
    std::jthread thread_;
};

}  // namespace aifw
#endif  // _WIN32
