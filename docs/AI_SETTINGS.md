# AI-innstillinger

## Oversikt

AI-Firewall støtter både lokal ONNX-modell og eksterne AI-API-er (OpenAI, Azure, egendefinert).

## GUI

Høyreklikk på tray-ikonet → **AI-innstillinger …**

| Felt | Beskrivelse |
|------|-------------|
| Aktiver AI | Slår AI-beslutninger av/på |
| Type | Lokal ONNX, OpenAI, Azure, eller egendefinert |
| API-nøkkel | For eksterne API-er (maskeres i UI) |
| Endpoint | URL for API-kall |
| Modellnavn | F.eks. `gpt-4o-mini` |
| Blokker ved score ≥ | Terskel for blokkering (0.0–1.0) |
| Tillat ved score ≤ | Terskel for tillatelse (0.0–1.0) |

## IPC-kommando

```json
{"cmd": "set_ai_config", "config": {
  "enabled": true,
  "provider": "openai",
  "api_key": "sk-...",
  "endpoint": "https://api.openai.com/v1/chat/completions",
  "model_name": "gpt-4o-mini",
  "timeout_ms": 5000,
  "block_threshold": 0.90,
  "allow_threshold": 0.30
}}
```

Svar:
```json
{"type": "reply", "cmd": "set_ai_config", "ok": true}
```

## Sikkerhet

- API-nøkkel sendes bare når brukeren skriver inn en ny verdi
- Nøkkelen lagres ikke i klartekst i config.json (bruk Windows Credential Manager i produksjon)
- Status-svar inneholder `has_api_key: true/false`, aldri selve nøkkelen

## Leverandører

| Provider | Beskrivelse |
|----------|-------------|
| `local` | Lokal ONNX-modell (standard) |
| `openai` | OpenAI Chat Completions API |
| `azure` | Azure OpenAI Service |
| `custom` | Egendefinert HTTP-endpoint |
