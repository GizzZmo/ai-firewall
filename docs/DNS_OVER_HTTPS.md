# DNS-over-HTTPS (DoH)

## Oversikt

`DohClient` gir krypterte DNS-oppslag via HTTPS, og unngår at DNS-spørringer er synlige i klartekst.

## Støttede leverandører

| Leverandør | Endpoint |
|------------|----------|
| Cloudflare | `https://cloudflare-dns.com/dns-query` |
| Google | `https://dns.google/resolve` |

## Bruk

```cpp
#include "DohClient.hpp"

// Standard (Cloudflare)
aifw::DohClient client;

// Forward lookup
auto ips = client.resolve("example.com");
if (ips) {
    for (const auto& ip : *ips) {
        // bruk ip
    }
}

// Reverse lookup
auto hostname = client.reverseLookup(0x08080808);  // 8.8.8.8
if (hostname) {
    // *hostname == "dns.google"
}

// Med Google og DNSSEC
aifw::DohConfig cfg;
cfg.provider = aifw::DohProvider::Google;
cfg.dnssec = true;
cfg.timeoutMs = 5000;
aifw::DohClient googleClient(cfg);
```

## Integrasjon med DnsResolver

For å bruke DoH i stedet for systemets DNS:

```cpp
class DnsResolver {
    // ...
private:
    std::optional<DohClient> doh_;  // Hvis satt, bruk DoH
};
```

## Sikkerhet

| Aspekt | Detalj |
|--------|--------|
| Kryptering | TLS 1.2+ |
| Personvern | DNS-spørringer skjult fra nettverksobservatører |
| DNSSEC | Valgfritt via `do=1` |
| Timeout | Konfigurerbar (standard 3s) |

## Begrensninger

- Krever internett-tilgang til DoH-leverandør
- Legger til latens (HTTPS-handshake)
- Avhengig av tredjepart (Cloudflare/Google)

## Anbefaling

Bruk DoH for:
- Logging av hostnavn (ikke real-time blokkering)
- Situasjoner der DNS-personvern er viktig

Bruk system-DNS for:
- Real-time oppslag der latens er kritisk
- Offline-scenarier
