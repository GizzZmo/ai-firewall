# TCP Timeout-mekanismer

AI-Firewall bruker tilstandsspesifikke timeouts for å rydde opp i forbindelser som ikke lenger er aktive.

## Standardverdier

| Tilstand | Timeout | Begrunnelse |
|----------|---------|-------------|
| SYN_SENT | 30 s | Connection attempt – de fleste OS bruker 21–75 s |
| SYN_RECEIVED | 30 s | Half-open – unngå SYN-flom-opphopning |
| ESTABLISHED | 5 min | Idle-forbindelser (kan økes for langvarige tjenester) |
| FIN_WAIT_1/2 | 60 s | Lukking pågår |
| CLOSE_WAIT | 60 s | Venter på at lokal applikasjon lukker |
| LAST_ACK | 30 s | Nesten ferdig |
| TIME_WAIT | 2 min | 2MSL (Maximum Segment Lifetime). Ofte 60–240 s |
| CLOSED | 10 s | Beholdes kort for logging |

## Hvordan det virker

1. Når en forbindelse går inn i en ny tilstand, lagres `stateEnteredAt`.
2. `processTimeouts(now)` sammenligner `now - stateEnteredAt` med timeout for tilstanden.
3. Utløpte forbindelser fjernes.

## Anbefalinger for brannmur

- **SYN_SENT / SYN_RECEIVED**: Hold relativt kort (15–45 s) for å begrense half-open-angrep.
- **ESTABLISHED**: 5–15 min er vanlig. Øk for applikasjoner med lange idle-perioder (SSH, databaser).
- **TIME_WAIT**: 60–120 s er trygt. For kort verdi kan gi problemer med delayed packets.
- Kjør `processTimeouts()` jevnlig (f.eks. hvert 5.–10. sekund) fra en bakgrunnstråd.

## Konfigurasjon

Timeouts kan settes ved konstruksjon:

```cpp
aifw::TcpTimeouts cfg;
cfg.established = 600000; // 10 min
cfg.timeWait = 60000;     // 1 min
aifw::TcpStateMachine sm(cfg);
```

Se også `src/core/TcpStateMachine.*`.
