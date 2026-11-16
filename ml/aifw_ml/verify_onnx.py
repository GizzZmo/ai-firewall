"""Verifiserer at ONNX-modellen oppfører seg som scikit-learn-modellen og som C++ forventer.

  python -m aifw_ml.verify_onnx --onnx out/flow_classifier.onnx --sklearn out/flow_classifier.joblib

Sjekker:
  1. input-navn/-form = feature_schema.json ("features", [N, 20], float32)
  2. output 'probabilities' er en float-tensor [N, 2] (zipmap=False)
  3. maks avvik mot sklearn predict_proba < toleranse
  4. noen kjente scenarier gir forventet retning (flom > surfing)
  5. latens per batch (mål på din maskin – C++ batcher opptil ai.max_batch rader)
"""
from __future__ import annotations

import argparse
import sys
import time

import joblib
import numpy as np
import onnxruntime as ort

from .schema import FEATURES, N_FEATURES, ONNX_INPUT_NAME


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--onnx", default="out/flow_classifier.onnx")
    ap.add_argument("--sklearn", default="out/flow_classifier.joblib")
    ap.add_argument("--samples", default="out/test_samples.npy")
    ap.add_argument("--tolerance", type=float, default=1e-4)
    a = ap.parse_args()
    ok = True

    sess = ort.InferenceSession(a.onnx, providers=["CPUExecutionProvider"])
    inp = sess.get_inputs()[0]
    outs = [o.name for o in sess.get_outputs()]
    print(f"input: {inp.name} {inp.shape} {inp.type}; outputs: {outs}")
    if inp.name != ONNX_INPUT_NAME or inp.shape[1] != N_FEATURES or inp.type != "tensor(float)":
        print("FEIL: input stemmer ikke med feature_schema.json"); ok = False
    if "probabilities" not in outs:
        print("FEIL: mangler 'probabilities'-output (eksporter med zipmap=False)"); ok = False
    meta = sess.get_modelmeta().custom_metadata_map
    if meta.get("aifw_features") != ",".join(FEATURES):
        print("FEIL: feature-liste i modellens metadata matcher ikke skjemaet"); ok = False

    X = np.load(a.samples).astype(np.float32)
    onnx_p = sess.run(["probabilities"], {inp.name: X})[0]
    if onnx_p.ndim != 2 or onnx_p.shape[1] != 2:
        print(f"FEIL: probabilities har form {onnx_p.shape}"); ok = False
    sk = joblib.load(a.sklearn)
    sk_p = sk.predict_proba(X)
    diff = float(np.abs(onnx_p - sk_p).max())
    print(f"maks |onnx - sklearn| = {diff:.2e} over {len(X)} rader")
    if diff > a.tolerance:
        print("FEIL: avvik over toleranse"); ok = False

    # Retningssjekk med håndlagde vektorer.
    def vec(**kw):
        v = np.zeros(N_FEATURES, dtype=np.float32)
        for k, val in kw.items():
            v[FEATURES.index(k)] = val
        return v
    flood = vec(duration_sec=0.05, fwd_packets=500, syn_count=500, pkt_len_mean=44, packets_per_sec=10000,
                bytes_per_sec=440000, fwd_bytes=22000, fwd_bwd_ratio=500, protocol_tcp=1, dst_port_norm=80 / 65535)
    browse = vec(duration_sec=3.0, fwd_packets=20, bwd_packets=60, fwd_bytes=8000, bwd_bytes=70000, pkt_len_mean=980,
                 pkt_len_std=500, iat_mean_ms=40, iat_std_ms=60, syn_count=1, psh_count=20, fin_count=1,
                 payload_entropy_mean=7.2, protocol_tcp=1, dst_port_norm=443 / 65535, packets_per_sec=26,
                 bytes_per_sec=26000, fwd_bwd_ratio=0.33)
    p = sess.run(["probabilities"], {inp.name: np.stack([flood, browse])})[0][:, 1]
    print(f"P(ondsinnet): SYN-flom={p[0]:.3f}, surfing={p[1]:.3f}")
    if not p[0] > p[1]:
        print("FEIL: modellen rangerer SYN-flom lavere enn surfing"); ok = False

    for batch in (1, 32):
        xb = np.repeat(X[:1], batch, axis=0)
        sess.run(["probabilities"], {inp.name: xb})
        t0 = time.perf_counter()
        for _ in range(200):
            sess.run(["probabilities"], {inp.name: xb})
        print(f"latens batch={batch}: {(time.perf_counter() - t0) / 200 * 1000:.3f} ms")

    # Referanse for C++-testen OnnxModel.MatchesPythonReference (tests/test_onnx_model.cpp).
    import json
    from pathlib import Path
    ref = {"features": X[:32].tolist(), "p_malicious": onnx_p[:32, 1].tolist()}
    ref_path = Path(a.onnx).with_name("reference_predictions.json")
    ref_path.write_text(json.dumps(ref))
    print(f"skrev referanse for C++-test: {ref_path}")

    print("OK" if ok else "VERIFISERING FEILET")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
