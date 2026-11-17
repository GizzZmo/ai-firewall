# GitHub Actions Caching

## Oversikt

Caching kan redusere CI-tid betydelig ved å gjenbruke avhengigheter og bygde artefakter.

## Caching-strategier

### 1. vcpkg Binary Caching

**Anbefalt for Windows-builds.**

```yaml
- name: Cache vcpkg
  uses: actions/cache@v4
  with:
    path: |
      ${{ github.workspace }}/vcpkg/installed
      ${{ github.workspace }}/vcpkg/packages
    key: vcpkg-${{ runner.os }}-${{ hashFiles('vcpkg.json') }}
    restore-keys: |
      vcpkg-${{ runner.os }}-
```

**Alternativ: lukka/run-vcpkg**

```yaml
- uses: lukka/run-vcpkg@v11
  with:
    vcpkgGitCommitId: 'master'
    runVcpkgInstall: true
```

### 2. ccache (Linux)

**Anbefalt for Linux-builds.**

```yaml
- name: Cache ccache
  uses: actions/cache@v4
  with:
    path: ~/.ccache
    key: ccache-${{ runner.os }}-${{ github.sha }}
    restore-keys: |
      ccache-${{ runner.os }}-

- name: Configure with ccache
  run: |
    cmake -B build -S . \
      -DCMAKE_C_COMPILER_LAUNCHER=ccache \
      -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
```

### 3. FetchContent/ExternalProject

```yaml
- name: Cache dependencies
  uses: actions/cache@v4
  with:
    path: ${{ github.workspace }}/.deps
    key: deps-${{ hashFiles('CMakeLists.txt', 'cmake/*.cmake') }}
```

## Anbefalt oppsett for ai-firewall

| Plattform | Strategi | Forventet besparelse |
|-----------|----------|---------------------|
| Windows | vcpkg binary cache | 5-15 min |
| Linux | ccache | 1-3 min |
| Begge | WinDivert cache | 10-30 sek |

## Implementasjon

Se oppdatert `.github/workflows/ci.yml` for konkret implementasjon.

## Begrensninger

| Begrensning | Verdi |
|-------------|-------|
| Cache-størrelse | 10 GB per repo |
| Cache-alder | 7 dager uten bruk |
| Cache-nøkkel | Maks 512 tegn |

## Feilsøking

**Cache miss:**
- Sjekk at nøkkelen er korrekt
- Verifiser at `hashFiles` matcher endrede filer

**Cache for stor:**
- Reduser ccache-størrelse: `ccache --max-size=500M`
- Ekskluder debug-symboler

## Referanser

- [actions/cache](https://github.com/actions/cache)
- [lukka/run-vcpkg](https://github.com/lukka/run-vcpkg)
- [ccache](https://ccache.dev/)
