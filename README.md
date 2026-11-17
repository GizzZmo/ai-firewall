# AI-Firewall

[![CI](https://github.com/GizzZmo/ai-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/GizzZmo/ai-firewall/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GizzZmo/ai-firewall)](https://github.com/GizzZmo/ai-firewall/releases)
[![Downloads](https://img.shields.io/github/downloads/GizzZmo/ai-firewall/total)](https://github.com/GizzZmo/ai-firewall/releases)
[![License](https://img.shields.io/github/license/GizzZmo/ai-firewall)](LICENSE)

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
- **DNS-over-HTTPS/TLS** for krypterte oppslag
- **Per-app-statistikk** og «spør brukeren»-dialog
- **GeoIP** for landskode i hendelser
- **Gruppe-basert tilgang** for GUI-kommandoer
- **Qt 6 tray-app** med named pipe IPC
- **WinUI 3-skeleton** for native Windows 11-opplevelse

## Artifacts og screenshots

### Build artifacts
- **Windows build ZIP:** Lastes opp fra CI og knyttes til release assets
- **ML verification:** Genereres under CI for modellvalidering

### Screenshot gallery

<p align="center">
  <img src="https://raw.githubusercontent.com/GizzZmo/ai-firewall/main/.github/assets/screenshots/ai-firewall-main.png" alt="AI-Firewall hovedskjerm" width="800" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/GizzZmo/ai-firewall/main/.github/assets/screenshots/ai-firewall-rules.png" alt="AI-Firewall regler" width="800" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/GizzZmo/ai-firewall/main/.github/assets/screenshots/ai-firewall-logs.png" alt="AI-Firewall logger" width="800" />
</p>

> **Merk:** Screenshots legges til når GUI-en er klar for demonstrasjon.

## Arkitektur

```
┌──────────────────────────────────────────────────────────┐
│                    GUI (Qt 6 / WinUI 3)                     │
│              named pipe IPC (JSON Lines)                   │
├──────────────────────────────────────────────────────────┤
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
└──────────────────────────────────────────────────────────┘
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
| DnsResolver | `src/core/DnsResolver.*` | Reverse DNS med cache |
| DnsParser | `src/core/DnsParser.*` | DNS wire-format parser |
| DohClient | `src/core/DohClient.*` | DNS-over-HTTPS |
| DotClient | `src/core/DotClient.*` | DNS-over-TLS |
| SchannelTls | `src/core/SchannelTls.*` | TLS-klient (Schannel) |
| DnsEnricher | `src/core/DnsEnricher.*` | Beriker hendelser |
| AppStats | `src/core/AppStats.*` | Per-app-statistikk |
| AppPromptHandler | `src/core/AppPromptHandler.*` | «Spør brukeren» |
| AccessControl | `src/core/AccessControl.*` | Gruppe-basert tilgang |
| CredentialStore | `src/core/CredentialStore.*` | API-nøkkel-lagring |
| AIDecisionEngine | `src/core/AIDecisionEngine.*` | ONNX-inferens |

## Dokumentasjon

| Dokument | Innhold |
|----------|---------|
| [docs/WINUI3_ARCHITECTURE.md](docs/WINUI3_ARCHITECTURE.md) | WinUI 3-vurdering |
| [docs/WINDOWS_ACCESS_CONTROL.md](docs/WINDOWS_ACCESS_CONTROL.md) | Access Control |
| [docs/ACL_REPLICATION.md](docs/ACL_REPLICATION.md) | ACL-replikering |
| [docs/AI_SETTINGS.md](docs/AI_SETTINGS.md) | AI-innstillinger |
| [docs/CREDENTIAL_STORE.md](docs/CREDENTIAL_STORE.md) | Credential Manager |
| [docs/DNS_OVER_HTTPS.md](docs/DNS_OVER_HTTPS.md) | DoH-klient |
| [docs/DNS_OVER_TLS.md](docs/DNS_OVER_TLS.md) | DoT-klient |
| [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) | Sikkerhetsgjennomgang |
| [docs/SOURCE_INVENTORY.md](docs/SOURCE_INVENTORY.md) | Kildefil-inventar |

## Veikart

- [ ] Verifisere og profilere på Windows 11 (MSVC), inkl. stress-test (iperf3) og latensmåling
- [x] Vertsnivå-features (portskanning, brute force)
- [x] TCP RST / ICMP unreachable (IPv4 + IPv6)
- [x] TCP State Machine (RFC 793)
- [x] Eksport av ekte flyter for trening
- [x] Modellversjonering + hot-reload
- [x] DNS-oppslag i loggen
- [x] DNS-over-HTTPS/TLS
- [x] Per-app-statistikk og «spør brukeren» (kjerne klar)
- [~] WinUI 3-variant (skeleton klar)
- [~] Fuzzing av pakkeparseren
- [x] Gruppe-basert tilgang
- [x] API-nøkkel-lagring (Credential Manager)

## Lisens

MIT – se [LICENSE](LICENSE).

## Bidrag

Pull requests er velkomne. For større endringer, åpne en issue først.
