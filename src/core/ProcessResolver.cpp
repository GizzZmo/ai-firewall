#ifdef _WIN32
#include "ProcessResolver.hpp"

#include <windivert.h>

#include <spdlog/spdlog.h>

namespace aifw {
namespace {

/// WinDivert FLOW-laget gir adresser som UINT32[4] i *host*-rekkefølge, med IPv4 som
/// IPv4-mapped IPv6 (::ffff:a.b.c.d). I host-rekkefølge ligger det minst signifikante
/// 32-bits ordet i [0], så ::ffff:a.b.c.d blir {a.b.c.d, 0x0000FFFF, 0, 0}.
IpAddress fromFlowAddr(const UINT32 a[4]) {
    if (a[3] == 0 && a[2] == 0 && a[1] == 0x0000FFFF) return IpAddress::v4(a[0]);
    IpAddress ip;
    ip.version = 6;
    for (int w = 0; w < 4; ++w) {
        const UINT32 word = a[3 - w];  // mest signifikante ord først
        ip.bytes[w * 4 + 0] = static_cast<std::uint8_t>(word >> 24);
        ip.bytes[w * 4 + 1] = static_cast<std::uint8_t>(word >> 16);
        ip.bytes[w * 4 + 2] = static_cast<std::uint8_t>(word >> 8);
        ip.bytes[w * 4 + 3] = static_cast<std::uint8_t>(word);
    }
    return ip;
}

}  // namespace

ProcessResolver::ProcessResolver() = default;
ProcessResolver::~ProcessResolver() { stop(); }

void ProcessResolver::start() {
    // "true" = alle flyter. SNIFF: vi påvirker ingenting. RECV_ONLY: vi sender aldri.
    handle_ = WinDivertOpen("true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (handle_ == INVALID_HANDLE_VALUE) win::throwLastError("WinDivertOpen(FLOW)");
    thread_ = std::jthread([this](std::stop_token st) { loop(st); });
    spdlog::info("ProcessResolver startet (WinDivert FLOW-lag)");
}

void ProcessResolver::stop() {
    if (handle_ != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_BOTH);  // vekker WinDivertRecv med ERROR_NO_DATA
    }
    if (thread_.joinable()) {
        thread_.request_stop();
        thread_.join();
    }
    if (handle_ != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
}

void ProcessResolver::loop(std::stop_token st) {
    WINDIVERT_ADDRESS addr{};
    while (!st.stop_requested()) {
        if (!WinDivertRecv(handle_, nullptr, 0, nullptr, &addr)) {
            const DWORD err = GetLastError();
            if (err == ERROR_NO_DATA || err == ERROR_OPERATION_ABORTED) break;  // shutdown
            spdlog::warn("WinDivertRecv(FLOW) feilet: {}", win::lastErrorMessage(err));
            continue;
        }
        const auto& f = addr.Flow;
        FlowKey key;
        key.localIp = fromFlowAddr(f.LocalAddr);
        key.remoteIp = fromFlowAddr(f.RemoteAddr);
        key.localPort = f.LocalPort;
        key.remotePort = f.RemotePort;
        key.protocol = static_cast<Protocol>(f.Protocol);

        if (addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED) {
            ProcessInfo info{f.ProcessId, pathForPid(f.ProcessId)};
            std::lock_guard lock(mutex_);
            if (flows_.size() > 500'000) flows_.clear();  // vern mot ubegrenset vekst
            flows_[key] = std::move(info);
        } else if (addr.Event == WINDIVERT_EVENT_FLOW_DELETED) {
            std::lock_guard lock(mutex_);
            flows_.erase(key);
        }
    }
}

std::optional<ProcessInfo> ProcessResolver::lookup(const FlowKey& key) const {
    std::lock_guard lock(mutex_);
    auto it = flows_.find(key);
    if (it == flows_.end()) return std::nullopt;
    return it->second;
}

std::size_t ProcessResolver::size() const {
    std::lock_guard lock(mutex_);
    return flows_.size();
}

std::string ProcessResolver::pathForPid(std::uint32_t pid) const {
    if (pid == 0) return {};
    if (pid == 4) return "System";
    {
        std::lock_guard lock(pidMutex_);
        if (auto it = pidPaths_.find(pid); it != pidPaths_.end()) return it->second;
    }
    std::string path;
    win::UniqueHandle proc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (proc) {
        std::wstring buf(32768, L'\0');  // maks lengde for utvidede stier
        DWORD size = static_cast<DWORD>(buf.size());
        if (QueryFullProcessImageNameW(proc.get(), 0, buf.data(), &size)) {
            buf.resize(size);
            path = win::toUtf8(buf);
        }
    }
    std::lock_guard lock(pidMutex_);
    // PID-er gjenbrukes av Windows; en enkel størrelsesgrense holder cachen fersk nok.
    if (pidPaths_.size() > 4096) pidPaths_.clear();
    pidPaths_[pid] = path;
    return path;
}

}  // namespace aifw
#endif  // _WIN32
