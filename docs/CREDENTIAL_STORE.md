# Credential Store

## Oversikt

API-nøkler lagres sikkert i **Windows Credential Manager**, ikke i klartekst i config-filer.

## Bruk

```cpp
#include "CredentialStore.hpp"

// Lagre
aifw::CredentialStore::store("openai", "sk-...");
aifw::CredentialStore::store("grok", "xai-...");
aifw::CredentialStore::store("gemini", "AIza...");

// Hent
auto key = aifw::CredentialStore::load("openai");
if (key) {
    // bruk *key
}

// Sjekk om eksisterer
if (aifw::CredentialStore::exists("grok")) {
    // nøkkel er lagret
}

// Slett
aifw::CredentialStore::remove("openai");
```

## Target-navn

Nøkler lagres med target `AiFirewall/<provider>`:
- `AiFirewall/openai`
- `AiFirewall/grok`
- `AiFirewall/gemini`
- `AiFirewall/azure`
- `AiFirewall/custom`

## Sikkerhet

| Aspekt | Detalj |
|--------|--------|
| Lagring | Windows Credential Manager (DPAPI-beskyttet) |
| Synlighet | Synlig i Credential Manager under "Generic Credentials" |
| Tilgang | Kun gjeldende bruker |
| Persistens | `CRED_PERSIST_LOCAL_MACHINE` |

## Integrasjon med AI-innstillinger

Når brukeren lagrer AI-innstillinger via GUI:
1. API-nøkkel sendes via IPC (`set_ai_config`)
2. Tjenesten kaller `CredentialStore::store(provider, apiKey)`
3. Nøkkelen lagres i Credential Manager
4. Config-fil inneholder bare `has_api_key: true`, ikke selve nøkkelen

Ved oppstart:
1. Tjenesten sjekker `CredentialStore::exists(provider)`
2. Hvis ja, laster nøkkelen med `load()`
3. Bruker nøkkelen for API-kall

## Begrensninger

- Krever Windows (Credential Manager er Windows-spesifikt)
- Maks 512 bytes per nøkkel (CRED_TYPE_GENERIC-grense)
- Ikke tilgjengelig under SYSTEM-konto uten profil lasting
