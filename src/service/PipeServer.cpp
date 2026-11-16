#ifdef _WIN32
#include "PipeServer.hpp"

#include <sddl.h>

#include <spdlog/spdlog.h>

#include "IpcProtocol.hpp"

namespace aifw {

namespace {
constexpr DWORD kBufSize = 64 * 1024;
constexpr std::size_t kMaxOutbox = 2000;
// SYSTEM + Administratorer: full. Interaktive brukere (IU): les/skriv (for GUI uten elevering).
constexpr const wchar_t* kSddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Venter på overlapped I/O eller stopp-signal. Returnerer false ved stopp/feil.
bool waitIo(HANDLE pipe, OVERLAPPED& ov, HANDLE stopEvent, DWORD& bytes, DWORD timeoutMs = INFINITE) {
    HANDLE events[2] = {ov.hEvent, stopEvent};
    const DWORD w = WaitForMultipleObjects(2, events, FALSE, timeoutMs);
    if (w != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &ov);
        GetOverlappedResult(pipe, &ov, &bytes, TRUE);  // vent til kanselleringen er ferdig
        return false;
    }
    return GetOverlappedResult(pipe, &ov, &bytes, FALSE) == TRUE;
}
}  // namespace

PipeServer::PipeServer(std::string pipeName, Handler handler, std::size_t maxClients)
    : pipePath_(L"\\\\.\\pipe\\" + win::toWide(pipeName)), handler_(std::move(handler)), maxClients_(maxClients) {
    stopEvent_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stopEvent_) win::throwLastError("CreateEvent");
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kSddl, SDDL_REVISION_1, &sd_, nullptr))
        win::throwLastError("ConvertStringSecurityDescriptorToSecurityDescriptorW");
}

PipeServer::~PipeServer() {
    stop();
    if (sd_) LocalFree(sd_);
}

void PipeServer::start() {
    acceptThread_ = std::jthread([this](std::stop_token st) { acceptLoop(st); });
    senderThread_ = std::jthread([this](std::stop_token st) { senderLoop(st); });
    spdlog::info("IPC: lytter på {}", win::toUtf8(pipePath_));
}

void PipeServer::stop() {
    SetEvent(stopEvent_.get());
    if (acceptThread_.joinable()) { acceptThread_.request_stop(); acceptThread_.join(); }
    if (senderThread_.joinable()) { senderThread_.request_stop(); outCv_.notify_all(); senderThread_.join(); }
    std::list<std::unique_ptr<Client>> clients;
    {
        std::lock_guard lock(clientsMutex_);
        clients.swap(clients_);
    }
    for (auto& c : clients) {
        if (c->reader.joinable()) { c->reader.request_stop(); c->reader.join(); }
    }
}

HANDLE PipeServer::createPipeInstance() {
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd_, FALSE};
    return CreateNamedPipeW(pipePath_.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                            PIPE_UNLIMITED_INSTANCES, kBufSize, kBufSize, 0, &sa);
}

void PipeServer::reapDeadClients() {
    std::list<std::unique_ptr<Client>> dead;
    {
        std::lock_guard lock(clientsMutex_);
        for (auto it = clients_.begin(); it != clients_.end();) {
            if (!(*it)->alive) {
                dead.push_back(std::move(*it));
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& c : dead)
        if (c->reader.joinable()) c->reader.join();  // tråden har allerede avsluttet
}

void PipeServer::acceptLoop(std::stop_token st) {
    win::UniqueHandle connectEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    while (!st.stop_requested()) {
        reapDeadClients();
        win::UniqueHandle pipe(createPipeInstance());
        if (!pipe) {
            spdlog::error("CreateNamedPipe feilet: {}", win::lastErrorMessage());
            if (WaitForSingleObject(stopEvent_.get(), 1000) == WAIT_OBJECT_0) return;
            continue;
        }
        OVERLAPPED ov{};
        ov.hEvent = connectEvent.get();
        ResetEvent(ov.hEvent);
        bool connected = ConnectNamedPipe(pipe.get(), &ov) != FALSE;
        if (!connected) {
            const DWORD e = GetLastError();
            if (e == ERROR_PIPE_CONNECTED) {
                connected = true;
            } else if (e == ERROR_IO_PENDING) {
                DWORD dummy = 0;
                connected = waitIo(pipe.get(), ov, stopEvent_.get(), dummy);
            }
        }
        if (!connected) continue;

        std::lock_guard lock(clientsMutex_);
        if (clients_.size() >= maxClients_) {
            spdlog::warn("IPC: maks antall klienter ({}) nådd – avviser", maxClients_);
            continue;  // pipe lukkes av RAII
        }
        auto c = std::make_unique<Client>();
        c->pipe = std::move(pipe);
        Client* raw = c.get();
        c->reader = std::jthread([this, raw](std::stop_token cst) { clientLoop(cst, raw); });
        clients_.push_back(std::move(c));
        spdlog::info("IPC: klient tilkoblet ({} aktive)", clients_.size());
    }
}

void PipeServer::clientLoop(std::stop_token st, Client* c) {
    win::UniqueHandle readEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    ipc::LineDecoder decoder;
    std::string buf(kBufSize, '\0');
    while (!st.stop_requested()) {
        OVERLAPPED ov{};
        ov.hEvent = readEvent.get();
        ResetEvent(ov.hEvent);
        DWORD n = 0;
        BOOL ok = ReadFile(c->pipe.get(), buf.data(), kBufSize, &n, &ov);
        if (!ok) {
            const DWORD e = GetLastError();
            if (e != ERROR_IO_PENDING && e != ERROR_MORE_DATA) break;
            if (!waitIo(c->pipe.get(), ov, stopEvent_.get(), n)) break;
        } else {
            GetOverlappedResult(c->pipe.get(), &ov, &n, FALSE);
        }
        if (n == 0) continue;
        for (const auto& msg : decoder.feed(std::string_view(buf.data(), n))) {
            // Sjekk klientens rettigheter ved å impersonere den kort.
            bool isAdmin = false;
            if (ImpersonateNamedPipeClient(c->pipe.get())) {
                isAdmin = win::isElevatedAdmin();
                RevertToSelf();
            }
            nlohmann::json reply;
            try {
                reply = handler_(msg, isAdmin);
            } catch (const std::exception& e) {
                reply = ipc::makeError(msg.value("cmd", std::string()), e.what());
            }
            if (!writeTo(*c, ipc::encode(reply))) break;
        }
    }
    DisconnectNamedPipe(c->pipe.get());
    c->alive = false;
    spdlog::info("IPC: klient frakoblet");
}

bool PipeServer::writeTo(Client& c, const std::string& data) {
    std::lock_guard lock(c.writeMutex);
    if (!c.alive) return false;
    win::UniqueHandle ev(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    OVERLAPPED ov{};
    ov.hEvent = ev.get();
    DWORD n = 0;
    if (!WriteFile(c.pipe.get(), data.data(), static_cast<DWORD>(data.size()), &n, &ov)) {
        if (GetLastError() != ERROR_IO_PENDING) return false;
        // Treg klient: gi opp etter 1 s i stedet for å holde igjen andre.
        if (!waitIo(c.pipe.get(), ov, stopEvent_.get(), n, 1000)) return false;
    }
    return n == data.size();
}

void PipeServer::broadcast(const nlohmann::json& msg) {
    {
        std::lock_guard lock(outMutex_);
        if (outbox_.size() >= kMaxOutbox) outbox_.pop_front();  // eldste kastes under press
        outbox_.push_back(ipc::encode(msg));
    }
    outCv_.notify_one();
}

void PipeServer::senderLoop(std::stop_token st) {
    while (!st.stop_requested()) {
        std::string data;
        {
            std::unique_lock lock(outMutex_);
            if (!outCv_.wait(lock, st, [this] { return !outbox_.empty(); })) return;
            data = std::move(outbox_.front());
            outbox_.pop_front();
        }
        // clientsMutex_ holdes under skrivingen slik at ingen klient kan fjernes (reapes)
        // mens vi skriver til den. writeTo har 1 s timeout, så låsen holdes ikke lenge.
        std::lock_guard lock(clientsMutex_);
        for (auto& c : clients_) {
            if (c->alive && !writeTo(*c, data)) {
                c->alive = false;
                CancelIoEx(c->pipe.get(), nullptr);  // vekker lesetråden så den avslutter
            }
        }
    }
}

}  // namespace aifw
#endif  // _WIN32
