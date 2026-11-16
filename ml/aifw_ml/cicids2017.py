"""Laster CIC-IDS2017 (MachineLearningCVE-CSV-ene) og mapper kolonner til vårt skjema.

Last ned: https://www.unb.ca/cic/datasets/ids-2017.html  (MachineLearningCSV.zip)
Bruk:     python -m aifw_ml.train --cicids "C:/data/MachineLearningCVE/*.csv"

VIKTIGE FORSKJELLER (les før du stoler på resultatene):
  * CICFlowMeter måler payload-lengder ("Total Length of Fwd Packets"), vi måler hele
    IP-pakken. Vi legger på et estimat av header-lengde (40 byte/pakke) for å nærme oss.
  * Datasettet har ikke payload-entropi -> settes til 0 (og modellen lærer å ignorere den).
    Bland gjerne inn egne data med ekte entropi.
  * Protokoll finnes ikke i MachineLearningCVE-filene -> utledes grovt fra port (53/123 = UDP).
  * CICFlowMeter-flyter avsluttes ved FIN eller 120 s timeout; våre ved FIN/RST eller
    konfigurerte timeouts, og vi vurderer også *delvise* flyter (etter 4, 68, ... pakker).
  * Datasettet har kjente feil (dupliserte rader, feilmerking, Inf/NaN). Vi fjerner Inf/NaN.
    Se Engelen et al. 2021 "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study".
Kort sagt: bra for å eksperimentere, men valider alltid på trafikk fra ditt eget nett.
"""
from __future__ import annotations

import glob

import numpy as np
import pandas as pd

from .schema import FEATURES

HEADER_ESTIMATE = 40

COLUMN_MAP = {
    "Destination Port": "dst_port",
    "Flow Duration": "flow_duration_us",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_payload",
    "Total Length of Bwd Packets": "bwd_payload",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Flow IAT Mean": "iat_mean_us",
    "Flow IAT Std": "iat_std_us",
    "SYN Flag Count": "syn_count",
    "FIN Flag Count": "fin_count",
    "RST Flag Count": "rst_count",
    "PSH Flag Count": "psh_count",
    "Label": "label_text",
}

UDP_PORTS = {53, 67, 68, 123, 137, 138, 161, 500, 1900, 5353}


def load(pattern: str, max_rows_per_file: int | None = None) -> pd.DataFrame:
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(f"ingen CSV-filer matcher {pattern}")
    frames = []
    for f in files:
        df = pd.read_csv(f, nrows=max_rows_per_file, low_memory=False, encoding="latin-1")
        df.columns = [c.strip() for c in df.columns]  # kolonnenavnene har ledende mellomrom
        missing = [c for c in COLUMN_MAP if c not in df.columns]
        if missing:
            raise ValueError(f"{f}: mangler kolonner {missing}")
        frames.append(df[list(COLUMN_MAP)].rename(columns=COLUMN_MAP))
    raw = pd.concat(frames, ignore_index=True)
    return to_schema(raw)


def to_schema(raw: pd.DataFrame) -> pd.DataFrame:
    r = raw.replace([np.inf, -np.inf], np.nan).dropna()
    duration = r.flow_duration_us.clip(lower=0) / 1e6
    eff = duration.clip(lower=1e-3)
    fwd_bytes = r.fwd_payload + HEADER_ESTIMATE * r.fwd_packets
    bwd_bytes = r.bwd_payload + HEADER_ESTIMATE * r.bwd_packets
    pkts = r.fwd_packets + r.bwd_packets
    port = r.dst_port.astype(int)
    is_udp = port.isin(UDP_PORTS)
    out = pd.DataFrame({
        "duration_sec": duration,
        "fwd_packets": r.fwd_packets,
        "bwd_packets": r.bwd_packets,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "pkt_len_mean": r.pkt_len_mean + HEADER_ESTIMATE,
        "pkt_len_std": r.pkt_len_std,
        "iat_mean_ms": r.iat_mean_us / 1000.0,
        "iat_std_ms": r.iat_std_us / 1000.0,
        "syn_count": r.syn_count,
        "fin_count": r.fin_count,
        "rst_count": r.rst_count,
        "psh_count": r.psh_count,
        "payload_entropy_mean": 0.0,
        "dst_port_norm": port / 65535.0,
        "protocol_tcp": (~is_udp).astype(float),
        "protocol_udp": is_udp.astype(float),
        "packets_per_sec": pkts / eff,
        "bytes_per_sec": (fwd_bytes + bwd_bytes) / eff,
        "fwd_bwd_ratio": r.fwd_packets / (r.bwd_packets + 1),
    })
    out = out[FEATURES].astype(np.float32)
    out["label"] = (r.label_text.str.strip().str.upper() != "BENIGN").astype(int).values
    out["scenario"] = r.label_text.str.strip().values
    return out.reset_index(drop=True)
