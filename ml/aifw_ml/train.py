"""Trener flyt-klassifiserer og eksporterer til ONNX for C++ (ONNX Runtime).

Eksempler:
  python -m aifw_ml.train                                  # syntetiske data
  python -m aifw_ml.train --data data/synthetic_flows.csv
  python -m aifw_ml.train --cicids "D:/MachineLearningCVE/*.csv" --mix-synthetic
  python -m aifw_ml.train --model mlp

Output (standard i ml/out/):
  flow_classifier.onnx   -> kopier til <installmappe>/models/ (se config.json ai.model_path)
  flow_classifier.joblib -> brukes av verify_onnx.py
  metrics.json           -> evaluering inkl. falsk-positiv-rate ved block_threshold
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .schema import FEATURES, N_FEATURES, ONNX_INPUT_NAME, SCHEMA_VERSION


def build_model(kind: str, seed: int):
    if kind == "rf":
        # Trær trenger ingen skalering og håndterer de store verdiområdene (bytes/s) fint.
        return RandomForestClassifier(n_estimators=120, max_depth=18, min_samples_leaf=3, class_weight="balanced",
                                      n_jobs=-1, random_state=seed)
    if kind == "mlp":
        # NB: MLP er følsom for skala; StandardScaler eksporteres som del av ONNX-grafen.
        return Pipeline([("scale", StandardScaler()),
                         ("mlp", MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, early_stopping=True,
                                               random_state=seed))])
    raise ValueError(f"ukjent modelltype {kind}")


def evaluate(y_true: np.ndarray, proba: np.ndarray, block_threshold: float, allow_threshold: float) -> dict:
    pred_block = (proba >= block_threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred_block, labels=[0, 1]).ravel()
    gray = float(((proba > allow_threshold) & (proba < block_threshold)).mean())
    return {
        "roc_auc": float(roc_auc_score(y_true, proba)) if len(np.unique(y_true)) > 1 else None,
        "block_threshold": block_threshold,
        "allow_threshold": allow_threshold,
        "false_positive_rate_at_block": float(fp / max(fp + tn, 1)),  # godartede flyter som ville blitt blokkert
        "detection_rate_at_block": float(tp / max(tp + fn, 1)),
        "gray_zone_fraction": gray,
        "confusion_at_block": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "report_at_0_5": classification_report(y_true, (proba >= 0.5).astype(int), output_dict=True, zero_division=0),
    }


def export_onnx(model, path: Path, opset: int = 17) -> None:
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    final = model.steps[-1][1] if isinstance(model, Pipeline) else model
    # zipmap=False gir 'probabilities' som float-tensor [N,2] – det C++-koden forventer.
    onx = convert_sklearn(model, initial_types=[(ONNX_INPUT_NAME, FloatTensorType([None, N_FEATURES]))],
                          options={id(final): {"zipmap": False}}, target_opset={"": opset, "ai.onnx.ml": 3})
    meta = onx.metadata_props.add()
    meta.key, meta.value = "aifw_feature_schema_version", str(SCHEMA_VERSION)
    meta = onx.metadata_props.add()
    meta.key, meta.value = "aifw_features", ",".join(FEATURES)
    onx.doc_string = "AI-Firewall flow classifier. Output 'probabilities'[:,1] = P(malicious)."
    path.write_bytes(onx.SerializeToString())


def main() -> None:
    ap = argparse.ArgumentParser(description="Tren og eksporter AI-Firewall-modell")
    ap.add_argument("--data", help="CSV med kolonnene i feature_schema.json + 'label'")
    ap.add_argument("--cicids", help="glob til CIC-IDS2017 MachineLearningCVE-CSV-er")
    ap.add_argument("--mix-synthetic", action="store_true", help="bland inn syntetiske data (gir entropi-signal)")
    ap.add_argument("--flows", type=int, default=5000, help="antall syntetiske flyter")
    ap.add_argument("--model", choices=["rf", "mlp"], default="rf")
    ap.add_argument("--block-threshold", type=float, default=0.9)
    ap.add_argument("--allow-threshold", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="out")
    a = ap.parse_args()

    frames = []
    if a.data:
        frames.append(pd.read_csv(a.data))
    if a.cicids:
        from .cicids2017 import load
        frames.append(load(a.cicids))
    if not frames or a.mix_synthetic:
        from .synthetic import generate
        t0 = time.time()
        frames.append(generate(n_flows=a.flows, seed=a.seed))
        print(f"Genererte syntetiske data på {time.time() - t0:.1f}s")
    df = pd.concat(frames, ignore_index=True)
    missing = [c for c in FEATURES + ["label"] if c not in df.columns]
    if missing:
        raise SystemExit(f"datasettet mangler kolonner: {missing}")

    X = df[FEATURES].to_numpy(dtype=np.float32)
    y = df["label"].to_numpy(dtype=np.int64)
    if not np.isfinite(X).all():
        raise SystemExit("datasettet inneholder NaN/Inf – rens det først")
    print(f"Datasett: {len(df)} rader, {y.mean():.1%} ondsinnet, {N_FEATURES} features")

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=a.seed)
    model = build_model(a.model, a.seed)
    t0 = time.time()
    model.fit(X_tr, y_tr)
    print(f"Trent {a.model} på {time.time() - t0:.1f}s")

    proba = model.predict_proba(X_te)[:, 1]
    metrics = evaluate(y_te, proba, a.block_threshold, a.allow_threshold)
    metrics.update({"model": a.model, "n_train": int(len(y_tr)), "n_test": int(len(y_te)),
                    "schema_version": SCHEMA_VERSION, "features": FEATURES})
    if "scenario" in df.columns:
        _, sc_te = train_test_split(df["scenario"].to_numpy(), test_size=0.25, stratify=y, random_state=a.seed)
        per = {}
        for s in np.unique(sc_te):
            m = sc_te == s
            per[str(s)] = {"n": int(m.sum()), "blocked_fraction": float((proba[m] >= a.block_threshold).mean())}
        metrics["per_scenario_blocked_fraction"] = per

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out / "flow_classifier.joblib")
    export_onnx(model, out / "flow_classifier.onnx")
    np.save(out / "test_samples.npy", X_te[:512])
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"ROC AUC: {metrics['roc_auc']:.4f}")
    print(f"Ved block_threshold={a.block_threshold}: deteksjon {metrics['detection_rate_at_block']:.1%}, "
          f"falske positive {metrics['false_positive_rate_at_block']:.2%}, gråsone {metrics['gray_zone_fraction']:.1%}")
    if "per_scenario_blocked_fraction" in metrics:
        for s, v in sorted(metrics["per_scenario_blocked_fraction"].items()):
            print(f"  {s:20s} n={v['n']:6d} blokkert={v['blocked_fraction']:.1%}")
    print(f"Skrev {out / 'flow_classifier.onnx'} – kjør verify_onnx for å kontrollere.")


if __name__ == "__main__":
    main()
