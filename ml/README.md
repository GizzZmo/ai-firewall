# ML-pipeline

```bash
pip install -r requirements.txt
python -m aifw_ml.synthetic --flows 6000 --out data/synthetic_flows.csv   # valgfritt: lagre datasett
python -m aifw_ml.train [--data data/synthetic_flows.csv] [--cicids "path/*.csv" --mix-synthetic] [--model rf|mlp]
python -m aifw_ml.verify_onnx
```

| Fil | Innhold |
|---|---|
| `feature_schema.json` | Feature-navn og rekkefølge – delt med C++ (`src/core/FeatureSchema.hpp`) |
| `aifw_ml/features.py` | Python-kopi av C++-beregningen (Welford, entropi, rater) |
| `aifw_ml/synthetic.py` | Syntetisk generator: 8 godartede + 6 ondsinnede scenarier |
| `aifw_ml/cicids2017.py` | Laster CIC-IDS2017 MachineLearningCVE og mapper til skjemaet |
| `aifw_ml/train.py` | Trening, evaluering (FPR ved terskel, gråsone, per scenario), ONNX-eksport |
| `aifw_ml/verify_onnx.py` | Sjekker input/output-navn, avvik mot sklearn, retning, latens; skriver referanse for C++-test |

Resultat i `out/`: `flow_classifier.onnx`, `flow_classifier.joblib`, `metrics.json`,
`test_samples.npy`, `reference_predictions.json`. Kopier ONNX-filen til `models/` ved siden av tjenesten.

Endrer du features: oppdater `feature_schema.json`, `FeatureSchema.hpp`, `features.py`,
`FeatureExtractor::extract` og `kFeatureSchemaVersion` – C++-testen `FeatureSchema.MatchesPythonSchema`
sier fra hvis noe er glemt.
