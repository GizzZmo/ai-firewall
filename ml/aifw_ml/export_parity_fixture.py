"""Lager tests/data/feature_parity.json: pakkesekvenser + features beregnet i Python.

C++-testen FeatureParity.PythonAndCppAgree spiller av de samme pakkene gjennom
FeatureExtractor/FlowTracker og sammenligner – slik oppdager vi om trening (Python) og
inferens (C++) beregner features ulikt.

  python -m aifw_ml.export_parity_fixture
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from .features import ACK, FIN, PSH, SYN, FlowState, Packet
from .schema import FEATURES

OUT = Path(__file__).resolve().parents[2] / "tests" / "data" / "feature_parity.json"


def main() -> None:
    rng = np.random.default_rng(1234)
    flows = []
    for i, (proto, port) in enumerate([(6, 443), (17, 53), (6, 8080), (17, 51820)]):
        st = FlowState(proto, port)
        t = 0.0
        pkts = []
        n = int(rng.integers(5, 40))
        for k in range(n):
            t += float(rng.exponential(0.02))
            outbound = bool(rng.random() < 0.6)
            plen = int(rng.integers(0, 400)) if rng.random() < 0.8 else 0
            kind = rng.random()
            payload = (rng.integers(0, 256, plen, dtype=np.uint8) if kind < 0.5
                       else np.frombuffer((b"GET /a HTTP/1.1 " * 40)[:plen], dtype=np.uint8)).tobytes()
            flags = 0
            if proto == 6:
                flags = ACK | (SYN if k == 0 else 0) | (PSH if plen else 0) | (FIN if k == n - 1 else 0)
            hdr = 40 if proto == 6 else 28
            p = Packet(round(t, 6), outbound, hdr + len(payload), flags, payload)
            st.update(p)
            pkts.append({"t_us": int(round(p.t * 1e6)), "outbound": outbound, "flags": flags, "payload_hex": payload.hex()})
        # Tid i fixturen er heltall mikrosekunder; regn features fra de avrundede tidene.
        st2 = FlowState(proto, port)
        for q in pkts:
            pl = bytes.fromhex(q["payload_hex"])
            st2.update(Packet(q["t_us"] / 1e6, q["outbound"], (40 if proto == 6 else 28) + len(pl), q["flags"], pl))
        flows.append({"protocol": proto, "remote_port": port, "local_port": 50000 + i, "packets": pkts,
                      "expected": dict(zip(FEATURES, [float(x) for x in st2.features()]))})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"features": FEATURES, "flows": flows}, indent=1))
    print(f"skrev {OUT} ({len(flows)} flyter)")


if __name__ == "__main__":
    main()
