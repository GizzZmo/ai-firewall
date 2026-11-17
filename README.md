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
| Pakkeavskjæring | WinDivert 2.2 (signert driver + user-mode API) | `src/core/PacketEngine.*` |
| Prosess/app per flyt | WinDivert FLOW-lag | `src/core/ProcessResolver.*` |
| Persistente regler | WFP (`FwpmEngineOpen0`, egen provider/sublayer, `FwpmFilterAdd0`) | `src/core/WfpManager.*` |
| Flytsporing | 5-tuple-tabell, tidsavbrudd, Welford-statistikk | `src/core/FlowTracker.*` |
| TCP State Machine | RFC 793-tilstander (SYN_SENT → ESTABLISHED → TIME_WAIT) | `src/core/TcpStateMachine.*` |
| Vertsnivå-deteksjon | Sliding window per remote-IP (unike porter, nye flyter, SYN) | `src/core/HostTracker.*` |
| Flyt-eksport | Anonymisert JSONL av utløpte flyter for ML-trening | `src/core/FlowExporter.*` |
| GeoIP | MaxMind GeoLite2 via libmaxminddb (valgfri) | `src/core/GeoIpLookup.*` |
| DNS reverse | `getnameinfo` + cache | `src/core/DnsResolver.*` |
| Features | Egen IPv4/IPv6/TCP/UDP-parser + `WinDivertHelperParsePacket`, Shannon-entropi | `src/core/FeatureExtractor.*`, `Entropy.*` |
| KI-inferens | ONNX Runtime, trådpool, batching, terskler, circuit breaker | `src/core/AIDecisionEngine.*`, `OnnxModel.cpp` |
| Regelmotor | JSON-regler: app, port(-område), IP/CIDR (v4/v6), retning, protokoll | `src/core/RuleEngine.*` |
| Beslutning | Regel → cache → host → standard + asynkron AI, læringsmodus, fail-safe | `src/core/DecisionCoordinator.*` |
| Reject-injeksjon | TCP RST (IPv4/IPv6 + extension headers) + ICMP/ICMPv6 Port Unreachable | `src/core/TcpResetInjector.*` |
| Læringsmodus | Registrerer trafikk, foreslår regler | `src/core/LearningMode.*` |
| Tjeneste | Windows-tjeneste, admin-sjekk, konsollmodus | `src/service/*` |
| IPC | Named pipe `\\\\.\\pipe\\aifw`, JSON Lines | `src/core/IpcProtocol.*`, `src/service/PipeServer.*` |
| GUI | Qt 6 system tray, varsler, logg, læringsbryter | `src/gui/*` |
| Logging | spdlog (konsoll + roterende fil) | `src/core/Log.*` |
| ML-pipeline | Python, scikit-learn → skl2onnx → verifisering | `ml/` |

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

*(Full README beholdt – kun veikart og komponenttabell oppdatert i denne committen. Se tidligere versjon for komplett innhold.)*
