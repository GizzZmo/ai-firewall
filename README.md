# AI-Firewall – KI-basert brannmur for Windows 11

> **Status: forsknings-/utviklingsprosjekt (v0.1).**

## Veikart

- [ ] Verifisere og profilere på Windows 11 (MSVC), inkl. stress-test (iperf3) og latensmåling
- [x] Vertsnivå-features (mange flyter fra samme kilde → portskanning, brute force)
- [x] TCP RST / ICMP unreachable ved blokkering (IPv4 + IPv6 med extension header-støtte, korrekte seq/ack)
- [x] TCP State Machine (RFC 793-tilstander integrert i feature extraction)
- [x] Eksport av ekte flyter fra tjenesten (anonymisert) for trening på egen trafikk
- [x] Modellversjonering + signert modellfil, hot-reload av modell
- [~] DNS-oppslag i loggen (`DnsEnricher` klar; full integrasjon i DecisionCoordinator gjenstår)
- [~] Per-app-statistikk og "spør brukeren"-dialog (`AppPromptHandler` klar; GUI-dialog gjenstår)
- [~] WinUI 3-variant av GUI-et (skeleton i `gui-winui/`; full implementasjon gjenstår)
- [~] Fuzzing av pakkeparseren (forbedret fuzzer; kjøring med corpus gjenstår)
- [~] Gruppe-basert tilgang for GUI-kommandoer (`AccessControl` klar)

## Nye komponenter

| Komponent | Fil |
|-----------|-----|
| DNS-beriking | `src/core/DnsEnricher.*` |
| App-prompt | `src/core/AppPromptHandler.*` |
| WinUI 3-skeleton | `gui-winui/` |
