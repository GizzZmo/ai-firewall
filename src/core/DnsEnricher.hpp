#pragma once
// Hjelpeklasse for å berike FirewallEvent med DNS-hostname.
// Kjøres asynkront for å unngå blokkering på pakkeveien.

#include <string>
#include <optional>
#include <cstdint>
#include <functional>
#include <memory>

namespace aifw {

class DnsResolver;
struct FirewallEvent;

class DnsEnricher {
public:
    explicit DnsEnricher(DnsResolver& resolver);

    // Berik en hendelse med hostname (blokkerer kort, bruker cache).
    // Kalles etter at pakken er reinjisert.
    void enrich(FirewallEvent& ev, uint32_t dstIpv4);

    // Asynkron variant: kaller callback når oppslag er ferdig.
    void enrichAsync(FirewallEvent ev, uint32_t dstIpv4,
                     std::function<void(FirewallEvent)> callback);

private:
    DnsResolver& resolver_;
};

} // namespace aifw
