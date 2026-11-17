# DNS-over-TLS (DoT)

## Oversikt

`DotClient` implementerer DNS-over-TLS (RFC 7858) – krypterte DNS-oppslag over TLS på port 853.

## DoT vs DoH

| Aspekt | DoT | DoH |
|--------|-----|-----|
| Port | 853 (dedikert) | 443 (delt med HTTPS) |
| Format | DNS wire-format | HTTP + JSON/wire |
| Identifiserbar | Ja (port 853) | Nei (ser ut som HTTPS) |
| Overhead | Bare TLS | HTTP + TLS |
| Blokkerbar | Enkelt | Vanskelig |

## Støttede servere

| Leverandør | Adresse | Port |
|------------|---------|------|
| Cloudflare | `1.1.1.1` | 853 |
| Google | `8.8.8.8` | 853 |
| Quad9 | `9.9.9.9` | 853 |

## Bruk

```cpp
#include "DotClient.hpp"

// Standard (Cloudflare)
aifw::DotClient client;

// Forward lookup
auto ips = client.resolve("example.com");

// Reverse lookup
auto hostname = client.reverseLookup(0x08080808);

// Egendefinert server
aifw::DotConfig cfg;
cfg.server = "8.8.8.8";
cfg.port = 853;
cfg.timeoutMs = 3000;
aifw::DotClient googleClient(cfg);
```

## Protokoll

DoT bruker standard DNS wire-format (RFC 1035) over TLS:

```
Client                          Server
  |                               |
  |--- TLS Handshake (port 853) ->|
  |<-- TLS Handshake OK ----------|
  |                               |
  |--- [2-byte len][DNS query] -->| 
  |<-- [2-byte len][DNS response]-|
  |                               |
```

## Sikkerhet

| Aspekt | Detalj |
|--------|--------|
| Kryptering | TLS 1.2+ |
| Sertifikatvalidering | Valgfri (standard: på) |
| Personvern | DNS-spørringer skjult |

## Begrensninger

- Krever full Schannel-implementasjon for produksjon
- Nåværende kode er et skeleton med forenklet TLS
- DNS-parsing håndterer ikke alle komprimeringstilfeller

## Status

Dette er et **skeleton**. Full produksjonsimplementasjon krever:
- Komplett Schannel TLS-handshake
- Sertifikatvalidering
- Full DNS wire-format parsing med komprimering
- Connection pooling
