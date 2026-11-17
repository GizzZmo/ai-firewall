#include "DnsEnricher.hpp"
#include "DnsResolver.hpp"
#include "Notifier.hpp"

#include <thread>

namespace aifw {

DnsEnricher::DnsEnricher(DnsResolver& resolver) : resolver_(resolver) {}

void DnsEnricher::enrich(FirewallEvent& ev, uint32_t dstIpv4) {
    auto host = resolver_.reverseLookup(dstIpv4);
    if (host) {
        if (!ev.message.empty()) ev.message += " ";
        ev.message += "(" + *host + ")";
    }
}

void DnsEnricher::enrichAsync(FirewallEvent ev, uint32_t dstIpv4,
                              std::function<void(FirewallEvent)> callback) {
    std::thread([this, ev = std::move(ev), dstIpv4, cb = std::move(callback)]() mutable {
        enrich(ev, dstIpv4);
        if (cb) cb(std::move(ev));
    }).detach();
}

} // namespace aifw
