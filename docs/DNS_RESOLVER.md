# DNS Reverse Lookup

`DnsResolver` gjør reverse DNS-oppslag for å vise domenenavn i logger i stedet for bare IP-adresser.

## Funksjoner

- Reverse lookup for IPv4 og IPv6
- In-memory cache med konfigurerbar TTL (standard 5 minutter)
- Trådsikker
- Returnerer `std::nullopt` ved feil eller manglende PTR-record

## Bruk

```cpp
aifw::DnsResolver dns;

uint32_t ip = 0x08080808; // 8.8.8.8
auto name = dns.reverseLookup(ip);
if (name) {
    log.info("Blokkert: {} ({})", *name, ip);
} else {
    log.info("Blokkert: {}", ip);
}
```

## Anbefalinger

- Kjør oppslag **asynkront** eller i en bakgrunnstråd – `getnameinfo` kan blokkere.
- Cache reduserer belastning ved gjentatte blokkeringer mot samme vert.
- Ikke bruk i den kritiske pakkeveien.
- Vurder å deaktivere hvis personvern er viktig (logger får da bare IP).

## Integrasjon

Kan kobles inn i:
- `DecisionCoordinator` ved blokkering
- GUI-varsler
- FlowExporter (valgfritt, anonymisert)

Se `src/core/DnsResolver.*`.
