# WinUI 3-arkitektur for AI-Firewall

## Konklusjon

**Anbefaling:** Behold Qt 6 for nå. Vurder WinUI 3 når:
- Du trenger MSIX/Store-distribusjon
- Fluent Design er viktigere enn kryssplattform
- Teamet har C#/.NET-kompetanse

WinUI 3 er det rette valget for en **ren Windows 11-opplevelse**, men krever mer arbeid for system tray og har ingen kryssplattform-støtte.

## Sammenligning

| Aspekt | Qt 6 (nåværende) | WinUI 3 |
|--------|---------------------|---------|
| Språk | C++ | C# eller C++ |
| Look & feel | Tilpassbar | Fluent Design (native) |
| System tray | Innebygd (`QSystemTrayIcon`) | Krever Win32-interop |
| MSIX/Store | Mulig, men mer arbeid | Førsteklasses støtte |
| Kryssplattform | Ja (Linux-sim) | Nei |
| Lisens | LGPL / kommersiell | MIT (Windows App SDK) |
| Modenhet | Svært moden | Moden, men noen hull |
| Minne/oppstart | Lav | Lav–middels |

## Anbefalt WinUI 3-arkitektur

```
┌─────────────────────────────────┐
│  Views (XAML)                     │  ← Mica, NavigationView, InfoBar
├────────────────────────────────┤
│  ViewModels (CommunityToolkit.Mvvm)│  ← Commands, binding
├────────────────────────────────┤
│  Services                          │  ← IpcClient, AppStats, AccessControl
├────────────────────────────────┤
│  IPC (named pipe)                  │  ← Samme protokoll som i dag
└────────────────────────────────┘
```

### System tray

WinUI 3 har **ikke** innebygd tray. Bruk:
- [SystemTrayWinUI3](https://github.com/MEHDIMYADI/SystemTrayWinUI3) (Win32-interop)
- Eller egen `NotifyIcon` via P/Invoke

### Viktige sider

| Side | Innhold |
|------|---------|
| Dashboard | Status, siste blokkeringer, læringsmodus-bryter |
| Logg | Filtrert hendelsesliste (med DNS-hostname) |
| Regler | Vis/rediger rules.json |
| App-prompt | ContentDialog når ny app oppdages |
| Innstillinger | Terskler, GeoIP, tema |

### MSIX-distribusjon

```xml
<!-- Package.appxmanifest -->
<Capabilities>
  <rescap:Capability Name="runFullTrust" />
</Capabilities>
```

Named pipe krever full trust. Alternativ: bruk App Service eller local loopback.

## Migreringsstrategi

1. **Behold tjenesten i C++** (WinDivert, WFP, ONNX).
2. **Bytt bare GUI** til WinUI 3 (C#).
3. IPC-protokollen er allerede JSON Lines – ingen endring nødvendig.
4. Start med tray + loggvindu, legg til app-prompt senere.

## Anbefaling for AI-Firewall

| Scenario | Valg |
|----------|------|
| Rask utvikling, Linux-sim viktig | **Qt 6** |
| Windows 11-native, Store-distribusjon | **WinUI 3** |
| Begge | Qt nå, WinUI 3 som alternativ GUI senere |

Se også:
- [WinUI 3 architecture patterns](https://learn.microsoft.com/en-us/windows/apps/develop/architecture-patterns)
- [System tray for WinUI 3](https://github.com/MEHDIMYADI/SystemTrayWinUI3)
