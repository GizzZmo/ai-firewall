# AI-innstillinger

## Oversikt

AI-Firewall støtter lokal ONNX-modell og eksterne AI-API-er.

## Støttede leverandører

| Provider | Beskrivelse | Standard endpoint | Standard modell |
|----------|-------------|-------------------|-----------------|
| `local` | Lokal ONNX-modell | – | `models/flow_classifier.onnx` |
| `openai` | OpenAI API | `https://api.openai.com/v1/chat/completions` | `gpt-4o-mini` |
| `azure` | Azure OpenAI | (bruker-definert) | `gpt-4o` |
| `gemini` | Google Gemini | `https://generativelanguage.googleapis.com/v1beta/models` | `gemini-2.0-flash` |
| `grok` | xAI Grok | `https://api.x.ai/v1/chat/completions` | `grok-3` |
| `custom` | Egendefinert | (bruker-definert) | (bruker-definert) |

## GUI

Høyreklikk på tray-ikonet → **AI-innstillinger …**

Når du velger en leverandør, oppdateres placeholder-tekstene automatisk.

## IPC-kommando

```json
{"cmd": "set_ai_config", "config": {
  "enabled": true,
  "provider": "grok",
  "api_key": "xai-...",
  "model_name": "grok-3",
  "block_threshold": 0.90
}}
```

## Sikkerhet

- API-nøkkel sendes bare når brukeren skriver inn en ny verdi
- Nøkkelen lagres ikke i klartekst i config.json
- Status-svar inneholder `has_api_key: true/false`, aldri selve nøkkelen
