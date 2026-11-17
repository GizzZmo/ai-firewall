# TCP Tilstandsmaskin

AI-Firewall bruker en forenklet, men korrekt TCP-tilstandsmaskin for å:

- Gi bedre features til AI-modellen (tilstand, varighet, half-open)
- Ta smartere beslutninger om RST-injeksjon
- Oppdage unormale mønstre (mange SYN_SENT uten ESTABLISHED)

## Tilstander

| Tilstand | Beskrivelse | Typisk bruk |
|----------|-------------|-------------|
| CLOSED | Ingen aktiv forbindelse | Start / etter RST |
| SYN_SENT | Klient har sendt SYN | Utgående forsøk |
| SYN_RECEIVED | Mottatt SYN, sendt SYN-ACK | Half-open |
| ESTABLISHED | Forbindelse er oppe | Normal data |
| FIN_WAIT_1 | Sendt FIN, venter ACK | Lukking startet |
| FIN_WAIT_2 | Mottatt ACK på FIN | Venter på andres FIN |
| CLOSE_WAIT | Mottatt FIN | Venter på lokal lukking |
| CLOSING | Samtidig FIN | Edge case |
| LAST_ACK | Sendt FIN etter mottatt FIN | Nesten ferdig |
| TIME_WAIT | Venter 2MSL | Ryddes etter timeout |

## Normal syklus

```
Client                          Server
  |                               |
  |-------- SYN ----------------->|  SYN_SENT
  |<------- SYN-ACK --------------|  ESTABLISHED (etter ACK)
  |-------- ACK ----------------->|
  |                               |
  |<======= Data ================>|
  |                               |
  |-------- FIN ----------------->|  FIN_WAIT_1
  |<------- ACK ------------------|  FIN_WAIT_2
  |<------- FIN ------------------|
  |-------- ACK ----------------->|  TIME_WAIT
```

## Implementasjon

Se `src/core/TcpStateMachine.*` (eller tilsvarende i din gren).

Nøkkelpunkter:
- Kanonisk 5-tuple (unngår duplikater for begge retninger)
- RST setter alltid tilstanden til CLOSED
- Half-open (SYN_SENT uten ESTABLISHED) kan brukes som signal til AI
- TIME_WAIT ryddes etter konfigurert timeout (standard 120 s)
