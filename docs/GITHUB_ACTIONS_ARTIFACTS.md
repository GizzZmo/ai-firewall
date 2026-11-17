# GitHub Actions Artifacts

## Oversikt

Artifacts er filer som lagres etter en workflow-kjøring. De kan lastes ned manuelt eller brukes av senere jobs.

## Nøkkelkonsepter

### Upload vs Download

| Action | Formål |
|--------|--------|
| `upload-artifact` | Laster opp filer fra en job |
| `download-artifact` | Laster ned filer til en senere job |

### Retention

| Innstilling | Standard | Anbefalt |
|-------------|----------|----------|
| `retention-days` | 90 | 7-14 for CI, 30 for releases |

**Viktig:** Standard 90 dager kan fylle lagringskvoten raskt.

### Komprimering

| Nivå | Bruk |
|-------|-----|
| 0 | Allerede komprimerte filer (ZIP, tar.gz) |
| 1-3 | Rask opplasting, større filer |
| 6 | Standard (balanse) |
| 9 | Maksimal komprimering, tregere |

## Eksempler

### Enkel opplasting

```yaml
- name: Upload build
  uses: actions/upload-artifact@v4
  with:
    name: build-${{ github.sha }}
    path: build/output/
    retention-days: 7
    if-no-files-found: error
```

### Nedlasting i senere job

```yaml
- name: Download build
  uses: actions/download-artifact@v4
  with:
    name: build-${{ github.sha }}
    path: dist/
```

### Feillogger (kort retention)

```yaml
- name: Upload logs on failure
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: failure-logs
    path: logs/
    retention-days: 1
```

## Begrensninger

| Begrensning | Verdi |
|-------------|-------|
| Maks filstørrelse | 10 GB per artifact (anbefalt < 1 GB) |
| Maks artifacts per job | 500 |
| Retention | 1-90 dager (public), 1-400 (private) |
| Navnekollisjon | Samme navn i samme kjøring feiler (v4+) |

## Anbefalinger for ai-firewall

| Artifact | Retention | Begrunnelse |
|----------|-----------|-------------|
| Windows build ZIP | 14 dager | Manuell testing |
| ML artifacts | 7 dager | Modellvalidering |
| Feillogger | 1 dag | Debugging |

## Kostnad

- Gratis tier: 500 MB
- Overage: $0.25/GB/måned
- **Tips:** Sett `retention-days` lavt for å unngå kostnader

## Referanser

- [upload-artifact](https://github.com/actions/upload-artifact)
- [download-artifact](https://github.com/actions/download-artifact)
