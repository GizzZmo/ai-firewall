# AI-Firewall – KI-basert brannmur for Windows 11

> **Status: forsknings-/utviklingsprosjekt (v0.1).** Ikke sertifisert, ikke revidert, ikke
> ment som eneste beskyttelse av en produksjonsmaskin. Les [Viktige advarsler](#viktige-advarsler)
> og [docs/SECURITY.md](docs/SECURITY.md) før du kjører den.

AI-Firewall fanger nettverkstrafikk med **WinDivert**, bygger statistikk per flyt (5-tuple),
lar en **ONNX-modell** vurdere flyten **asynkront**, og håndhever eksplisitte regler fra
`rules.json`. Regler som skal overleve omstart legges inn i **Windows Filtering Platform (WFP)**.
Et **Qt 6**-ikon i system tray viser blokkeringer, logg og lar deg slå læringsmodus av/på.

| Komponent | Teknologi | Fil(er) |
|---|---|---|
| Pakkeavskjæring | WinDivert 2.2 | `src/core/PacketEngine.*` |
| Prosess/app per flyt | WinDivert FLOW-lag | `src/core/ProcessResolver.*` |
| Persistente regler | WFP | `src/core/WfpManager.*` |
| Flytsporing | 5-tuple + Welford | `src/core/FlowTracker.*` |
| TCP State Machine | RFC 793 | `src/core/TcpStateMachine.*` |
| Vertsnivå-deteksjon | Sliding window | `src/core/HostTracker.*` |
| Flyt-eksport | Anonymisert JSONL | `src/core/FlowExporter.*` |
| GeoIP | MaxMind GeoLite2 | `src/core/GeoIpLookup.*` |
| DNS reverse | getnameinfo + cache | `src/core/DnsResolver.*` |
| Features | IPv4/IPv6/TCP/UDP + entropi | `src/core/FeatureExtractor.*` |
| KI-inferens | ONNX Runtime | `src/core/AIDecisionEngine.*` |
| Regelmotor | JSON-regler | `src/core/RuleEngine.*` |
| Beslutning | Regel → cache → host → AI | `src/core/DecisionCoordinator.*` |
| Reject-injeksjon | TCP RST + ICMP | `src/core/TcpResetInjector.*` |
| Læringsmodus | Foreslår regler | `src/core/LearningMode.*` |
| Tjeneste | Windows Service | `src/service/*` |
| IPC | Named pipe | `src/core/IpcProtocol.*` |
| GUI | Qt 6 system tray | `src/gui/*` |
| Logging | spdlog | `src/core/Log.*` |
| ML-pipeline | Python → ONNX | `ml/` |

## Veikart

- [ ] Verifisere og profilere på Windows 11 (MSVC), inkl. stress-test (iperf3) og latensmåling
- [x] Vertsnivå-features (mange flyter fra samme kilde → portskanning, brute force)
- [x] TCP RST / ICMP unreachable ved blokkering (IPv4 + IPv6 med extension header-støtte, korrekte seq/ack)
- [x] TCP State Machine (RFC 793-tilstander integrert i feature extraction)
- [x] Eksport av ekte flyter fra tjenesten (anonymisert) for trening på egen trafikk
- [x] Modellversjonering + signert modellfil, hot-reload av modell
- [~] DNS-oppslag i loggen (`DnsResolver` med cache lagt til; integrasjon i DecisionCoordinator/GUI gjenstår)
- [ ] Per-app-statistikk og "spør brukeren"-dialog for nye apper (interaktiv modus)
- [ ] WinUI 3-variant av GUI-et, MSIX/WiX-installer med signering
- [ ] Fuzzing av pakkeparseren (libFuzzer) og ETW-logging
- [ ] Gruppe-basert tilgang for GUI-kommandoer (i stedet for kun administrator)

Se docs/ for mer detaljer (ARCHITECTURE.md, SECURITY.md, TCP_STATE_MACHINE.md, TCP_TIMEOUTS.md, DNS_RESOLVER.md).
