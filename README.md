# AI-Firewall – KI-basert brannmur for Windows 11

> **Status: forsknings-/utviklingsprosjekt (v0.1).**

## Veikart

- [ ] Verifisere og profilere på Windows 11 (MSVC), inkl. stress-test (iperf3) og latensmåling
- [x] Vertsnivå-features (mange flyter fra samme kilde → portskanning, brute force)
- [x] TCP RST / ICMP unreachable ved blokkering (IPv4 + IPv6 med extension header-støtte, korrekte seq/ack)
- [x] TCP State Machine (RFC 793-tilstander integrert i feature extraction)
- [x] Eksport av ekte flyter fra tjenesten (anonymisert) for trening på egen trafikk
- [x] Modellversjonering + signert modellfil, hot-reload av modell
- [~] DNS-oppslag i loggen (`DnsResolver` klar; integrasjonseksempel i docs/ROADMAP_PROGRESS.md)
- [~] Per-app-statistikk og "spør brukeren"-dialog (`AppStats` klar; GUI-dialog gjenstår)
- [ ] WinUI 3-variant av GUI-et, MSIX/WiX-installer med signering
- [~] Fuzzing av pakkeparseren (libFuzzer-skeleton i `fuzz/`; kjøring gjenstår)
- [~] Gruppe-basert tilgang for GUI-kommandoer (`AccessControl` klar; full Windows-gruppe-oppslag gjenstår)

Se [docs/ROADMAP_PROGRESS.md](docs/ROADMAP_PROGRESS.md) for integrasjonseksempler.

## Komponenter (utvalg)

| Komponent | Fil |
|-----------|-----|
| DNS reverse | `src/core/DnsResolver.*` |
| Per-app-statistikk | `src/core/AppStats.*` |
| Tilgangskontroll | `src/core/AccessControl.*` |
| Fuzzing | `fuzz/packet_parser_fuzzer.cpp` |

Full dokumentasjon og arkitektur finnes i tidligere commits og i `docs/`.
