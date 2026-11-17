# Kildefil-inventar

> Oppdatert 2026-11-17. Kartlegger hvilke filer som bygges og testes.

## Plattformuavhengig (aifw_core)

| Fil | Status | Testet |
|-----|--------|--------|
| Types.cpp | Aktiv | Ja |
| Entropy.cpp | Aktiv | Ja |
| FeatureExtractor.cpp | Aktiv | Ja |
| FlowTracker.cpp | Aktiv | Ja |
| HostTracker.cpp | Aktiv | Ja |
| FlowExporter.cpp | Aktiv | Delvis |
| RuleEngine.cpp | Aktiv | Ja |
| Config.cpp | Aktiv | Ja |
| VerdictCache.cpp | Aktiv | Ja |
| Notifier.cpp | Aktiv | Ja |
| Model.cpp | Aktiv | Ja |
| AIDecisionEngine.cpp | Aktiv | Ja |
| LearningMode.cpp | Aktiv | Ja |
| DecisionCoordinator.cpp | Aktiv | Ja |
| IpcProtocol.cpp | Aktiv | Ja |
| Log.cpp | Aktiv | Nei |
| FirewallCore.cpp | Aktiv | Delvis |
| GeoIpLookup.cpp | Aktiv | Nei |
| DnsResolver.cpp | Aktiv | Nei |
| DnsEnricher.cpp | Aktiv | Nei |
| DnsParser.cpp | Aktiv | Nei |
| DohClient.cpp | Aktiv | Nei |
| AppStats.cpp | Aktiv | Nei |
| AppPromptHandler.cpp | Aktiv | Nei |

## Windows-spesifikk (kun WIN32)

| Fil | Status | Testet |
|-----|--------|--------|
| FeatureExtractorWin.cpp | Aktiv | Nei |
| PacketEngine.cpp | Aktiv | Nei |
| ProcessResolver.cpp | Aktiv | Nei |
| WfpManager.cpp | Aktiv | Nei |
| WinUtil.cpp | Aktiv | Nei |
| AccessControl.cpp | Aktiv | Nei |
| CredentialStore.cpp | Aktiv | Nei |
| DotClient.cpp | Aktiv | Nei |
| SchannelTls.cpp | Aktiv | Nei |

## GUI (Qt 6)

| Fil | Status | Testet |
|-----|--------|--------|
| main.cpp | Aktiv | Nei |
| TrayApp.cpp | Aktiv | Nei |
| ServiceClient.cpp | Aktiv | Nei |
| LogWindow.cpp | Aktiv | Nei |
| SettingsDialog.cpp | Aktiv | Nei |

## Manglende tester (prioritert)

1. **DnsParser** – kritisk for DoT/DoH, bør ha enhetstester
2. **AppStats** – enkel logikk, lett å teste
3. **DnsResolver** – cache-logikk
4. **IpcProtocol** – allerede testet, men mangler edge cases

## Anbefaling

- Legg til tester for DnsParser (høyest prioritet)
- Legg til tester for AppStats og AppPromptHandler
- Windows-spesifikk kode testes manuelt eller med Windows CI
