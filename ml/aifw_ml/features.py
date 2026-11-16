"""Python-speil av C++-feature-beregningen (FlowTracker + FeatureExtractor::extract).

Formlene MÅ samsvare med C++:
  * Welford / utvalgs-standardavvik (n-1), 0 når n < 2
  * IAT beregnes mellom påfølgende pakker i flyten (begge retninger)
  * entropi: Shannon over maks 256 første payload-bytes, for de første 8 payload-pakkene
  * rater deler på max(varighet, 1 ms)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

from .schema import FEATURES

ENTROPY_SAMPLE_BYTES = 256
ENTROPY_SAMPLE_PACKETS = 8

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


class RunningStats:
    __slots__ = ("n", "mean", "m2")

    def __init__(self) -> None:
        self.n, self.mean, self.m2 = 0, 0.0, 0.0

    def add(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    def avg(self) -> float:
        return self.mean if self.n else 0.0

    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0


@dataclass
class Packet:
    t: float              # sekunder
    outbound: bool        # True = lokal -> remote (fwd)
    length: int           # IP-lengde
    flags: int = 0        # TCP-flagg
    payload: bytes = b""


@dataclass
class FlowState:
    protocol: int          # 6=TCP, 17=UDP, 1=ICMP
    remote_port: int
    first: float | None = None
    last: float | None = None
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    pkt_len: RunningStats = field(default_factory=RunningStats)
    iat_ms: RunningStats = field(default_factory=RunningStats)
    entropy: RunningStats = field(default_factory=RunningStats)
    syn: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0

    def update(self, p: Packet) -> None:
        if self.first is None:
            self.first = self.last = p.t
        else:
            self.iat_ms.add(max(0.0, (p.t - self.last) * 1000.0))
            self.last = p.t
        if p.outbound:
            self.fwd_packets += 1
            self.fwd_bytes += p.length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += p.length
        self.pkt_len.add(float(p.length))
        if self.protocol == 6:
            self.syn += bool(p.flags & SYN)
            self.fin += bool(p.flags & FIN)
            self.rst += bool(p.flags & RST)
            self.psh += bool(p.flags & PSH)
        if p.payload and self.entropy.n < ENTROPY_SAMPLE_PACKETS:
            self.entropy.add(shannon_entropy(p.payload[:ENTROPY_SAMPLE_BYTES]))

    def features(self) -> np.ndarray:
        duration = (self.last - self.first) if self.first is not None else 0.0
        eff = max(duration, 1e-3)
        pkts = self.fwd_packets + self.bwd_packets
        byts = self.fwd_bytes + self.bwd_bytes
        values = {
            "duration_sec": duration,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "pkt_len_mean": self.pkt_len.avg(),
            "pkt_len_std": self.pkt_len.std(),
            "iat_mean_ms": self.iat_ms.avg(),
            "iat_std_ms": self.iat_ms.std(),
            "syn_count": self.syn,
            "fin_count": self.fin,
            "rst_count": self.rst,
            "psh_count": self.psh,
            "payload_entropy_mean": self.entropy.avg(),
            "dst_port_norm": self.remote_port / 65535.0,
            "protocol_tcp": 1.0 if self.protocol == 6 else 0.0,
            "protocol_udp": 1.0 if self.protocol == 17 else 0.0,
            "packets_per_sec": pkts / eff,
            "bytes_per_sec": byts / eff,
            "fwd_bwd_ratio": self.fwd_packets / (self.bwd_packets + 1),
        }
        missing = set(FEATURES) - values.keys()
        if missing:
            raise RuntimeError(f"features.py mangler {missing} – oppdater i takt med FeatureSchema.hpp")
        return np.array([values[n] for n in FEATURES], dtype=np.float32)


def inference_points(n_packets: int, min_packets: int = 4, every: int = 64) -> list[int]:
    """Pakkeantall der C++ (DecisionCoordinator) kjører inferens: min, min+every, ..."""
    pts = list(range(min_packets, n_packets + 1, every)) if n_packets >= min_packets else []
    if n_packets not in pts:
        pts.append(n_packets)
    return pts
