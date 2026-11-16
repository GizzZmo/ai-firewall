// Named pipe-server (\\.\pipe\<navn>) for GUI-klienter. JSON Lines-protokoll (IpcProtocol.hpp).
//
// Sikkerhet:
//  * DACL: SYSTEM og Administratorer full tilgang, interaktive brukere lese/skrive.
//  * PIPE_REJECT_REMOTE_CLIENTS: ingen tilgang over nettverket (SMB).
//  * Tilstandsendrende kommandoer krever at klienten er elevert administrator
//    (sjekkes ved impersonering av klienten).
//  * Maks meldingsstørrelse og maks antall klienter.
#pragma once
#ifdef _WIN32

#include <windows.h>

#include <condition_variable>
#include <deque>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "Notifier.hpp"
#include "WinUtil.hpp"

namespace aifw {

class PipeServer {
public:
    /// handler(kommando, klientErAdmin) -> svar. Kalles fra klienttråder.
    using Handler = std::function<nlohmann::json(const nlohmann::json&, bool)>;

    PipeServer(std::string pipeName, Handler handler, std::size_t maxClients = 8);
    ~PipeServer();
    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;

    void start();
    void stop();

    /// Ikke-blokkerende: legger meldingen i utgående kø som sendes til alle klienter.
    void broadcast(const nlohmann::json& msg);

private:
    struct Client {
        win::UniqueHandle pipe;
        std::mutex writeMutex;
        std::atomic<bool> alive{true};
        std::jthread reader;
    };

    void acceptLoop(std::stop_token st);
    void clientLoop(std::stop_token st, Client* c);
    void senderLoop(std::stop_token st);
    bool writeTo(Client& c, const std::string& data);
    HANDLE createPipeInstance();
    void reapDeadClients();

    std::wstring pipePath_;
    Handler handler_;
    std::size_t maxClients_;
    win::UniqueHandle stopEvent_;
    PSECURITY_DESCRIPTOR sd_{nullptr};

    std::mutex clientsMutex_;
    std::list<std::unique_ptr<Client>> clients_;

    std::mutex outMutex_;
    std::condition_variable_any outCv_;
    std::deque<std::string> outbox_;

    std::jthread acceptThread_;
    std::jthread senderThread_;
};

/// INotifier som pusher hendelser til GUI-klientene.
class PipeNotifier final : public INotifier {
public:
    explicit PipeNotifier(PipeServer& server) : server_(server) {}
    void notify(const FirewallEvent& ev) override { server_.broadcast({{"type", "event"}, {"event", ev.toJson()}}); }

private:
    PipeServer& server_;
};

}  // namespace aifw
#endif  // _WIN32
