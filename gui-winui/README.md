# WinUI 3 GUI Skeleton for AI-Firewall

Minimal struktur for en WinUI 3-basert GUI som snakker med tjenesten via named pipe.

## Struktur

```
gui-winui/
├── AiFirewall.Gui/          # WinUI 3-prosjekt (C#)
│   ├── App.xaml
│   ├── MainWindow.xaml
│   ├── ViewModels/
│   ├── Services/
│   │   └── IpcClient.cs
│   └── Views/
└── README.md
```

## Opprett prosjekt

```powershell
# Krever Windows App SDK
dotnet new winui3 -n AiFirewall.Gui
```

## Nøkkelkomponenter

### IpcClient.cs
```csharp
public class IpcClient {
    private NamedPipeClientStream? pipe;
    
    public async Task ConnectAsync() {
        pipe = new NamedPipeClientStream(".", "AiFirewall", PipeDirection.InOut);
        await pipe.ConnectAsync(2000);
    }
    
    public async Task<JsonDocument> SendAsync(object cmd) {
        var json = JsonSerializer.Serialize(cmd) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        await pipe!.WriteAsync(bytes);
        // les svar...
    }
}
```

### App-prompt dialog
```csharp
public async Task<bool> ShowAppPrompt(string appPath) {
    var dialog = new ContentDialog {
        Title = "Ny applikasjon",
        Content = $"Tillat {Path.GetFileName(appPath)}?",
        PrimaryButtonText = "Tillat",
        CloseButtonText = "Blokker"
    };
    var result = await dialog.ShowAsync();
    return result == ContentDialogResult.Primary;
}
```

## Status

Dette er et **skeleton**. Full implementasjon krever:
- Windows App SDK installert
- Visual Studio 2022+
- System tray-interop (se SystemTrayWinUI3)

Se [docs/WINUI3_ARCHITECTURE.md](../docs/WINUI3_ARCHITECTURE.md).
