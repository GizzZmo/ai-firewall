"""Syntetisk datasett-generator.

Simulerer pakkesekvenser for typiske godartede og ondsinnede flyter og beregner features
med nøyaktig samme formler som C++ (features.py). Rader genereres ved de samme
pakkeantallene som C++ kjører inferens på (4, 68, 132, ...), så modellen lærer å
vurdere både tidlige og modne flyter.

VIKTIG: Syntetiske data er for å komme i gang og teste pipelinen end-to-end.
En modell for reell bruk må trenes/valideres på ekte trafikk (se cicids2017.py).
"""
from __future__ import annotations

import argparse
from typing import Callable, Iterator

import numpy as np
import pandas as pd

from .features import ACK, FIN, PSH, RST, SYN, FlowState, Packet, inference_points
from .schema import FEATURES

Rng = np.random.Generator


def _payload(rng: Rng, n: int, kind: str) -> bytes:
    if n <= 0:
        return b""
    if kind == "random":   # TLS/kryptert/komprimert
        return rng.integers(0, 256, n, dtype=np.uint8).tobytes()
    if kind == "text":     # HTTP/DNS-aktig
        alphabet = np.frombuffer(b"abcdefghijklmnopqrstuvwxyz0123456789 .-/:=\r\n", dtype=np.uint8)
        return rng.choice(alphabet, n).tobytes()
    return bytes(n)        # nuller / padding


def _tcp_handshake(t: float, rtt: float) -> list[Packet]:
    return [Packet(t, True, 52, SYN), Packet(t + rtt, False, 52, SYN | ACK), Packet(t + rtt * 1.05, True, 40, ACK)]


# ---- Godartede flyter ------------------------------------------------------------

def https_browse(rng: Rng) -> tuple[int, int, list[Packet]]:
    rtt = rng.uniform(0.005, 0.12)
    pk = _tcp_handshake(0.0, rtt)
    t = pk[-1].t
    for _ in range(rng.integers(3, 60)):
        t += rng.exponential(0.05)
        req = int(rng.integers(100, 1400))
        pk.append(Packet(t, True, 40 + req, PSH | ACK, _payload(rng, req, "random")))
        for _ in range(rng.integers(1, 12)):
            t += rng.exponential(rtt / 4) + 0.0005
            resp = int(rng.integers(500, 1460))
            pk.append(Packet(t, False, 40 + resp, ACK | (PSH if rng.random() < 0.3 else 0), _payload(rng, resp, "random")))
        t += rtt / 2
        pk.append(Packet(t, True, 40, ACK))
    t += rng.exponential(1.0)
    pk += [Packet(t, True, 40, FIN | ACK), Packet(t + rtt, False, 40, FIN | ACK), Packet(t + rtt * 1.1, True, 40, ACK)]
    return 6, 443, pk


def http_plain(rng: Rng) -> tuple[int, int, list[Packet]]:
    proto, _, pk = https_browse(rng)
    for p in pk:  # bytt payload til tekst for de første pakkene
        if p.payload:
            p.payload = _payload(rng, len(p.payload), "text")
    return proto, 80, pk


def dns_query(rng: Rng) -> tuple[int, int, list[Packet]]:
    t, pk = 0.0, []
    for _ in range(rng.integers(1, 4)):
        q = int(rng.integers(30, 80))
        pk.append(Packet(t, True, 28 + q, 0, _payload(rng, q, "text")))
        t += rng.uniform(0.005, 0.08)
        a = int(rng.integers(60, 300))
        pk.append(Packet(t, False, 28 + a, 0, _payload(rng, a, "text")))
        t += rng.exponential(0.5)
    return 17, 53, pk


def video_stream(rng: Rng) -> tuple[int, int, list[Packet]]:
    rtt = rng.uniform(0.01, 0.06)
    pk = _tcp_handshake(0.0, rtt)
    t = pk[-1].t
    for _ in range(rng.integers(20, 120)):
        t += rng.uniform(0.5, 2.0)  # segment-intervall
        for _ in range(rng.integers(10, 40)):
            t += rng.exponential(0.002)
            pk.append(Packet(t, False, 1500, ACK, _payload(rng, 1460, "random")))
            if rng.random() < 0.5:
                pk.append(Packet(t + 0.0003, True, 40, ACK))
    return 6, 443, pk


def ssh_interactive(rng: Rng) -> tuple[int, int, list[Packet]]:
    rtt = rng.uniform(0.01, 0.1)
    pk = _tcp_handshake(0.0, rtt)
    t = pk[-1].t
    for _ in range(rng.integers(20, 300)):
        t += rng.exponential(0.4)
        pk.append(Packet(t, True, 40 + 36, PSH | ACK, _payload(rng, 36, "random")))
        t += rtt
        pk.append(Packet(t, False, 40 + 36, PSH | ACK, _payload(rng, 36, "random")))
    return 6, 22, pk


def voip_udp(rng: Rng) -> tuple[int, int, list[Packet]]:
    t, pk = 0.0, []
    port = int(rng.integers(10000, 60000))
    for _ in range(rng.integers(100, 1500)):
        t += 0.02 + rng.normal(0, 0.002)
        pk.append(Packet(t, True, 200, 0, _payload(rng, 172, "random")))
        pk.append(Packet(t + rng.uniform(0, 0.01), False, 200, 0, _payload(rng, 172, "random")))
    return 17, port, pk


def bulk_download(rng: Rng) -> tuple[int, int, list[Packet]]:
    rtt = rng.uniform(0.005, 0.05)
    pk = _tcp_handshake(0.0, rtt)
    t = pk[-1].t
    pk.append(Packet(t, True, 300, PSH | ACK, _payload(rng, 260, "random")))
    for _ in range(rng.integers(300, 3000)):
        t += rng.exponential(0.0004)
        pk.append(Packet(t, False, 1500, ACK, _payload(rng, 1460, "random")))
        if rng.random() < 0.5:
            pk.append(Packet(t, True, 40, ACK))
    return 6, 443, pk


def ntp(rng: Rng) -> tuple[int, int, list[Packet]]:
    return 17, 123, [Packet(0.0, True, 76, 0, _payload(rng, 48, "random")),
                     Packet(rng.uniform(0.01, 0.1), False, 76, 0, _payload(rng, 48, "random"))]


# ---- Ondsinnede flyter -----------------------------------------------------------

def syn_flood(rng: Rng) -> tuple[int, int, list[Packet]]:
    t, pk = 0.0, []
    rate = rng.uniform(500, 20000)
    for _ in range(rng.integers(50, 3000)):
        t += rng.exponential(1 / rate)
        pk.append(Packet(t, True, 40 + int(rng.integers(0, 20)), SYN))
    return 6, int(rng.choice([80, 443, 22, 3389, 8080])), pk


def syn_scan_rejected(rng: Rng) -> tuple[int, int, list[Packet]]:
    # Gjentatte SYN-forsøk mot samme port som besvares med RST (f.eks. brute force mot lukket port).
    t, pk = 0.0, []
    for _ in range(rng.integers(5, 200)):
        t += rng.exponential(0.01)
        pk.append(Packet(t, True, 44, SYN))
        pk.append(Packet(t + 0.001, False, 40, RST | ACK))
    return 6, int(rng.integers(1, 1024)), pk


def udp_flood(rng: Rng) -> tuple[int, int, list[Packet]]:
    t, pk = 0.0, []
    rate = rng.uniform(1000, 50000)
    size = int(rng.integers(20, 1400))
    kind = rng.choice(["zero", "random"])
    for _ in range(rng.integers(100, 5000)):
        t += rng.exponential(1 / rate)
        pk.append(Packet(t, True, 28 + size, 0, _payload(rng, size, kind)))
    return 17, int(rng.integers(1, 65535)), pk


def exfil_udp(rng: Rng) -> tuple[int, int, list[Packet]]:
    t, pk = 0.0, []
    for _ in range(rng.integers(200, 4000)):
        t += rng.exponential(0.0008)
        n = int(rng.integers(900, 1400))
        pk.append(Packet(t, True, 28 + n, 0, _payload(rng, n, "random")))
        if rng.random() < 0.01:
            pk.append(Packet(t + 0.01, False, 60, 0, _payload(rng, 32, "random")))
    return 17, int(rng.integers(20000, 65535)), pk


def c2_beacon(rng: Rng) -> tuple[int, int, list[Packet]]:
    # Svært regelmessige, små utgående "heartbeats" over lang tid til høy port.
    rtt = rng.uniform(0.02, 0.2)
    pk = _tcp_handshake(0.0, rtt)
    t = pk[-1].t
    interval = rng.uniform(5, 60)
    for _ in range(rng.integers(10, 120)):
        t += interval * rng.normal(1.0, 0.02)
        n = int(rng.integers(40, 120))
        pk.append(Packet(t, True, 40 + n, PSH | ACK, _payload(rng, n, "random")))
        pk.append(Packet(t + rtt, False, 40 + 20, PSH | ACK, _payload(rng, 20, "random")))
    return 6, int(rng.choice([4444, 8443, 1337, 6667, 31337, int(rng.integers(10000, 65535))])), pk


def slowloris(rng: Rng) -> tuple[int, int, list[Packet]]:
    rtt = rng.uniform(0.01, 0.1)
    pk = _tcp_handshake(0.0, rtt)
    t = pk[-1].t
    for _ in range(rng.integers(20, 200)):
        t += rng.uniform(5, 15)
        pk.append(Packet(t, True, 40 + 8, PSH | ACK, _payload(rng, 8, "text")))
        pk.append(Packet(t + rtt, False, 40, ACK))
    return 6, 80, pk


BENIGN: list[tuple[Callable[[Rng], tuple[int, int, list[Packet]]], float]] = [
    (https_browse, 0.35), (http_plain, 0.08), (dns_query, 0.2), (video_stream, 0.08), (ssh_interactive, 0.06),
    (voip_udp, 0.08), (bulk_download, 0.1), (ntp, 0.05),
]
MALICIOUS: list[tuple[Callable[[Rng], tuple[int, int, list[Packet]]], float]] = [
    (syn_flood, 0.22), (syn_scan_rejected, 0.15), (udp_flood, 0.18), (exfil_udp, 0.17), (c2_beacon, 0.16),
    (slowloris, 0.12),
]


def _flow_rows(proto: int, port: int, packets: list[Packet], label: int, scenario: str,
               min_packets: int, every: int) -> Iterator[dict]:
    st = FlowState(proto, port)
    points = set(inference_points(len(packets), min_packets, every))
    for i, p in enumerate(packets, start=1):
        st.update(p)
        if i in points:
            row = dict(zip(FEATURES, st.features().tolist()))
            row["label"] = label
            row["scenario"] = scenario
            row["packets_seen"] = i
            yield row


def generate(n_flows: int = 6000, malicious_ratio: float = 0.35, seed: int = 7, min_packets: int = 4,
             every: int = 64, label_noise: float = 0.01) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows: list[dict] = []
    for _ in range(n_flows):
        mal = rng.random() < malicious_ratio
        table = MALICIOUS if mal else BENIGN
        fns, weights = zip(*table)
        fn = fns[rng.choice(len(fns), p=np.array(weights) / sum(weights))]
        proto, port, pk = fn(rng)
        label = int(mal)
        if rng.random() < label_noise:  # litt støy gjør modellen mindre overkonfident
            label = 1 - label
        rows.extend(_flow_rows(proto, port, pk, label, fn.__name__, min_packets, every))
    df = pd.DataFrame(rows)
    # Tidlige rader (få pakker) er ofte ikke separerbare – det er OK og ønsket:
    # modellen skal gi usikker score der, og terskler i C++ håndterer gråsonen.
    return df


def main() -> None:
    ap = argparse.ArgumentParser(description="Generer syntetisk flyt-datasett")
    ap.add_argument("--flows", type=int, default=6000)
    ap.add_argument("--malicious-ratio", type=float, default=0.35)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="data/synthetic_flows.csv")
    a = ap.parse_args()
    df = generate(a.flows, a.malicious_ratio, a.seed)
    from pathlib import Path
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False)
    print(f"Skrev {len(df)} rader ({df.label.mean():.1%} ondsinnet) til {a.out}")
    print(df.groupby("scenario").size().to_string())


if __name__ == "__main__":
    main()
