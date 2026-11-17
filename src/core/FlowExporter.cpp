#include "FlowExporter.hpp"

#include <functional>

#include <spdlog/spdlog.h>

namespace aifw {

FlowExporter::FlowExporter(std::filesystem::path path) : path_(std::move(path)) {
    out_.open(path_, std::ios::app);
    if (!out_) spdlog::warn("Kunne ikke åpne flow-eksportfil: {}", path_.string());
}

void FlowExporter::onExpired(const FlowKey& key, const FlowStats& s) {
    if (!out_) return;
    // Enkel anonymisering: hash av IP (ikke kryptografisk sterk, men nok for å unngå rå IP i fil).
    auto hashIp = [](const IpAddress& ip) {
        std::size_t h = ip.version;
        for (auto b : ip.bytes) h = h * 31 + b;
        return h;
    };

    nlohmann::json j = {
        {"remote_hash", hashIp(key.remoteIp)},
        {"local_hash", hashIp(key.localIp)},
        {"remote_port", key.remotePort},
        {"protocol", static_cast<int>(key.protocol)},
        {"duration_sec", std::chrono::duration<double>(s.lastSeen - s.firstSeen).count()},
        {"fwd_packets", s.fwdPackets},
        {"bwd_packets", s.bwdPackets},
        {"fwd_bytes", s.fwdBytes},
        {"bwd_bytes", s.bwdBytes},
        {"syn", s.synCount},
        {"fin", s.finCount},
        {"rst", s.rstCount},
        {"psh", s.pshCount},
        {"entropy_mean", s.entropy.mean()},
    };

    std::lock_guard lock(mutex_);
    out_ << j.dump() << '\n';
    if (++count_ % 100 == 0) out_.flush();
}

void FlowExporter::flush() {
    std::lock_guard lock(mutex_);
    out_.flush();
}

}  // namespace aifw
