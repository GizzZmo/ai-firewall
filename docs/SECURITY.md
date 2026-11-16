# Sikkerhet

AI-Firewall kjører med høyeste rettigheter og sitter i nettverksveien. Feil her kan både
åpne maskinen for angrep og stenge den ute fra nettet. Dette dokumentet beskriver
trusselmodell, designvalg og kjente begrensninger.

> **Ikke produksjonssertifisert.** Koden er ikke sikkerhetsrevidert, ikke penetrasjonstestet
> og ikke fuzzet. Bruk den sammen med – ikke i stedet for – Windows Defender Firewall og
> Microsoft Defender.

## Trusselmodell

| Angriper | Mål | Tiltak |
|---|---|---|
| Ondsinnet trafikk fra nettet | krasje/omgå parseren | Egen parser validerer alle lengder (IHL, total length, data offset, IPv6 ext. headers med løkkegrense) før lesing; avkortede pakker avvises. På Windows brukes `WinDivertHelperParsePacket`. Enhetstester dekker avkortede/korrupte pakker. |
| Ondsinnet trafikk | utmatte minne/CPU | Maks antall flyter (`flow.max_flows`), begrenset AI-kø, entropi kun på første 8×256 byte, LRU-cache med maks størrelse, begrenset læringstabell. |
| Lokal, uprivilegert bruker | slå av beskyttelsen via GUI-pipen | Pipe-DACL: SYSTEM/Administratorer full, interaktive brukere les/skriv. **Alle tilstandsendrende kommandoer krever elevert administrator** (sjekkes ved å impersonere klienten). `PIPE_REJECT_REMOTE_CLIENTS`. Maks 8 klienter, maks 64 KB per melding. |
| Lokal bruker | bytte ut modell/regler/konfig | Installer i `C:\Program Files\AI-Firewall` (kun admin-skriverett). Tjenesten leser filer relativt til sin egen exe-mappe. Se "Anbefalt installasjon". |
| Skadevare med admin | hva som helst | Utenfor modellen: med administrator kan angriper uansett stoppe tjenesten, laste egne drivere osv. |
| Adversarial ML | lure modellen (f.eks. etterligne surfing) | Ingen fullgod beskyttelse. Regler gjelder alltid før AI; AI blokkerer kun ved høy score (`block_threshold`); gråsone gir *ikke* blokkering. Bruk AI som ekstra lag, ikke eneste. |
| Forgiftet treningsdata | lære modellen å slippe gjennom angrep | Tren kun på data du kontrollerer; `verify_onnx.py` sjekker konsistens men ikke integritet. Veikart: signert modellfil. |

## Designvalg med sikkerhetskonsekvens

### Fail-open vs. fail-closed
- **WinDivert-delen er fail-open**: stopper/krasjer tjenesten, lukkes håndtaket og trafikken går
  normalt. Ukjente/uparsbare pakker slippes gjennom. Unntak i beslutningslogikken slipper pakken.
  Begrunnelse: en brannmur-prototype som låser maskinen ute er farligere enn en som midlertidig
  ikke filtrerer. **Konsekvens**: en angriper som klarer å krasje tjenesten, slår av filtreringen
  (tjenesten startes automatisk på nytt etter 5 s via SCM failure actions).
- **WFP-regler er alltid aktive** (også når tjenesten ikke kjører). Legg kritiske blokkeringer
  som `persistent: true`.
- Vil du ha fail-closed: legg inn en persistent WFP "block all"-regel med lav vekt og eksplisitte
  permit-regler for det du trenger. Gjør dette kun med fysisk tilgang til maskinen.

### WFP-arbitrering
Vår sublayer evalueres sammen med Windows Defender Firewall sine. I WFP vinner **block** over
**permit** på tvers av sublayers (med mindre en permit er "hard"). En `allow`-regel i AI-Firewall
kan derfor ikke åpne noe Defender Firewall blokkerer – men en `deny`-regel her blokkerer uansett.

### Læringsmodus
I læringsmodus blokkerer AI ingenting, men **eksplisitte deny-regler gjelder fortsatt**.
Regelforslag fra læringsmodus inkluderer allow-regler for alt som ble observert – også trafikk
fra eventuell skadevare som allerede er på maskinen. Gå gjennom forslagene før du bruker dem
(GUI-et ber om bekreftelse).

### App-identitet
- App-sti hentes fra WinDivert FLOW-laget (PID → `QueryFullProcessImageNameW`). PID-er gjenbrukes,
  og de aller første pakkene i en forbindelse kan komme før FLOW-hendelsen. App-regler i
  WinDivert-delen er derfor "beste innsats".
- Persistente app-regler i WFP bruker `FWPM_CONDITION_ALE_APP_ID` (kernel-verifisert sti) og er
  sterkere.
- Sti ≠ identitet: en angriper kan legge en fil med samme navn et annet sted. Bruk full sti i
  regler, og helst stier som kun admin kan skrive til. (Veikart: signatur-/hash-baserte regler.)

### Rettigheter
- Tjenesten kjører som `LocalSystem` (kreves for WinDivert og WFP). Veikart: egen tjeneste-SID
  med minimale privilegier der det er mulig.
- `aifw_service.exe` har UAC-manifest `requireAdministrator` (MSVC-bygg) og sjekker selv elevering
  (`CheckTokenMembership`) for alle kommandolinjevalg.
- Tjenesten registreres med sitert sti (unngår "unquoted service path"-sårbarheten) og avhenger av BFE.

## Personvern

- Logger (`logs/aifw.log`) og hendelser inneholder IP-adresser, porter og app-stier. Ingen
  payload lagres – payload brukes kun til entropiberegning i minnet.
- Læringsdata (`data/learning.json`) inneholder app-stier, porter og opptil 32 remote-IP-er per
  kombinasjon.
- Tren aldri en modell på andres trafikk uten samtykke; anonymiser IP-er før deling av datasett.

## Anbefalt installasjon

1. Kopier bygget til `C:\Program Files\AI-Firewall\` (arver admin-only skriverett).
2. Kontroller signaturen på `WinDivert64.sys` (`Get-AuthenticodeSignature`).
3. `aifw_service.exe --install` som administrator.
4. Kjør i læringsmodus i noen dager, gå gjennom logg og forslag.
5. Juster `ai.block_threshold` ut fra `metrics.json` (falsk-positiv-rate) og egen erfaring.
6. Slå av læringsmodus.

## Kjente begrensninger

- Ingen fuzzing av parser, IPC-dekoder eller JSON-innlasting (unntatt enhetstester med korrupte data).
- Ingen beskyttelse mot at modellfilen byttes ut av en administrator.
- AI vurderer én flyt om gangen; distribuerte mønstre (skanning, brute force over mange
  forbindelser) fanges ikke av AI i v0.1.
- IPv6 extension headers utover de vanligste (hop-by-hop, routing, fragment, destination options),
  f.eks. AH/ESP, behandles som "ukjent protokoll" uten porter – port-regler matcher da ikke.
- Ytelse under høy last er ikke målt. Fulle køer i WinDivert gir pakketap (kernel dropper etter
  `queue_time_ms`).

## Rapportering

Fant du en sårbarhet? Ikke opprett en offentlig sak; kontakt vedlikeholderen direkte.
