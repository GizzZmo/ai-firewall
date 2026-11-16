// WinDivert-basert pakkeavskjæring på NETWORK-laget.
//
//   Kernel (WinDivert64.sys)  --kø-->  WinDivertRecvEx (batch)  -->  parse  -->  decide()
//                                                                              |
//        <--  WinDivertSendEx (batch, kun tillatte pakker)  <-------------------+
//
// Blokkerte pakker droppes ved å IKKE reinjisere dem. Ingenting i denne løkken venter på
// AI: decide() er rask (regel/cache/standard) og AI kjører asynkront.
#pragma once
#ifdef _WIN32

#include <windows.h>

#include <atomic>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

#include "Config.hpp"
#include "DecisionCoordinator.hpp"
#include "Types.hpp"

namespace aifw {

class ProcessResolver;

struct PacketEngineStats {
    std::uint64_t received{0}, reinjected{0}, dropped{0}, parseErrors{0}, sendErrors{0}, batches{0};
};

class PacketEngine {
public:
    using Decider = std::function<Decision(const PacketInfo&)>;

    /// resolver kan være nullptr (ingen app-info). decider må være trådsikker.
    PacketEngine(WinDivertConfig cfg, Decider decider, ProcessResolver* resolver = nullptr);
    ~PacketEngine();  // stop() + lukk håndtak (RAII)
    PacketEngine(const PacketEngine&) = delete;
    PacketEngine& operator=(const PacketEngine&) = delete;

    /// Åpner WinDivert-håndtaket og starter arbeidertråder. Kaster ved feil
    /// (typisk: ikke administrator, driver mangler, ugyldig filter).
    void start();
    /// Stopper mottak, lar køen tømmes og joiner tråder. Idempotent.
    void stop();

    [[nodiscard]] PacketEngineStats stats() const noexcept;
    [[nodiscard]] bool running() const noexcept { return running_.load(); }

    /// Validerer et filter uten å åpne håndtak (WinDivertHelperCompileFilter).
    static bool validateFilter(const std::string& filter, std::string& error);

private:
    void workerLoop(std::stop_token st, unsigned index);

    WinDivertConfig cfg_;
    Decider decider_;
    ProcessResolver* resolver_;
    HANDLE handle_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> received_{0}, reinjected_{0}, dropped_{0}, parseErrors_{0}, sendErrors_{0}, batches_{0};
    std::vector<std::jthread> workers_;
};

}  // namespace aifw
#endif  // _WIN32
