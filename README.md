# AI-Firewall

**KI-basert brannmur for Windows 11** – bruker-modus pakkeavskjæring med WinDivert, tilstandsfølging, AI-beslutninger og moderne C++20.

> **Status:** forsknings-/utviklingsprosjekt (v0.1). Ikke klar for produksjon.

## Funksjoner

- **Pakkeavskjæring** via WinDivert (ingen kernel-driver nødvendig)
- **TCP State Machine** (RFC 793) med timeout-håndtering
- **RST/ICMP-injeksjon** for IPv4 og IPv6 (inkl. extension headers)
- **AI-beslutninger** via ONNX Runtime med circuit breaker
- **Regelmotor** med YAML-regler og cache
- **Vertsnivå-deteksjon** (portskanning, brute force)
- **DNS reverse lookup** med cache for lesbare logger
- **Per-app-statistikk** og «spør brukeren»-dialog
- **GeoIP** for landskode i hendelser
- **Gruppe-basert tilgang** for GUI-kommandoer
- **Qt 6 tray-app** med named pipe IPC
- **WinUI 3-skeleton** for native Windows 11-opplevelse

## Arkitektur

```
┌─────────────────────────────────────────────────────────┐
│                    GUI (Qt 6 / WinUI 3)                     │
│              named pipe IPC (JSON Lines)                   │
├─────────────────────────────────────────────────────────┤
│                    FirewallService                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐   │
│  │ PacketEngine│  │ Decision-  │  │ TcpReset- │   │
│  │ (WinDivert) │→ │ Coordinator│→ │ Injector   │   │
│  └────────────┘  └────────────┘  └────────────┘   │
│         │                 │                              │
│         ▼                 ▼                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐   │
│  │ FlowTracker │  │ AI Engine │  │ DnsResolver│   │
│  │ TcpState   │  │ (ONNX)    │  │ AppStats   │   │
│  └────────────┘  └────────────┘  └────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Bygging

### Krav

- Windows 11 (eller Windows 10 1809+)
- Visual Studio 2022 med C++20
- CMake 3.20+
- vcpkg (anbefalt)
- WinDivert 2.2+
- ONNX Runtime
- Qt 6 (for GUI)

### Steg

```powershell
git clone https://github.com/GizzZmo/ai-firewall.git
cd ai-firewall

# Med vcpkg
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

### Kjøring

```powershell
# Tjeneste (krever admin)
.\build\Release\aifw-service.exe

# GUI
.\build\Release\aifw-gui.exe
```

## Komponenter

| Komponent | Fil | Beskrivelse |
|-----------|-----|-------------|
| PacketEngine | `src/core/PacketEngine.*` | WinDivert-avskjæring |
| DecisionCoordinator | `src/core/DecisionCoordinator.*` | Beslutningslogikk |
| TcpStateMachine | `include/TcpStateMachine.h` | TCP-tilstander + timeout |
| TcpResetInjector | `include/TcpResetInjector.h` | RST/ICMP-injeksjon |
| DnsResolver | `src/core/DnsResolver.*` | Reverse DNS med cache |
| DnsEnricher | `src/core/DnsEnricher.*` | Beriker hendelser |
| AppStats | `src/core/AppStats.*` | Per-app-statistikk |
| AppPromptHandler | `src/core/AppPromptHandler.*` | «Spør brukeren» |
| AccessControl | `src/core/AccessControl.*` | Gruppe-basert tilgang |
| AIDecisionEngine | `src/core/AIDecisionEngine.*` | ONNX-inferens |

## Dokumentasjon

| Dokument | Innhold |
|----------|---------|
| [docs/WINUI3_ARCHITECTURE.md](docs/WINUI3_ARCHITECTURE.md) | WinUI 3-vurdering |
| [docs/WINDOWS_ACCESS_CONTROL.md](docs/WINDOWS_ACCESS_CONTROL.md) | Access Control |
| [docs/ACL_REPLICATION.md](docs/ACL_REPLICATION.md) | ACL-replikering |
| [docs/INTEGRATION_NOTES.md](docs/INTEGRATION_NOTES.md) | Integrasjonsveiledning |
| [docs/ROADMAP_PROGRESS.md](docs/ROADMAP_PROGRESS.md) | Fremdrift |

## Veikart

- [ ] Verifisere og profilere på Windows 11 (MSVC), inkl. stress-test (iperf3) og latensmåling
- [x] Vertsnivå-features (portskanning, brute force)
- [x] TCP RST / ICMP unreachable (IPv4 + IPv6)
- [x] TCP State Machine (RFC 793)
- [x] Eksport av ekte flyter for trening
- [x] Modellversjonering + hot-reload
- [x] DNS-oppslag i loggen
- [x] Per-app-statistikk og «spør brukeren» (kjerne klar)
- [~] WinUI 3-variant (skeleton klar)
- [~] Fuzzing av pakkeparseren
- [x] Gruppe-basert tilgang

## Lisens

MIT – se [LICENSE](LICENSE).

## Bidrag

Pull requests er velkomne. For større endringer, åpne en issue først.
