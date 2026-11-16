"""Leser feature-skjemaet som deles med C++ (src/core/FeatureSchema.hpp).

Én kilde til sannhet: ml/feature_schema.json. C++-testen FeatureSchema.MatchesPythonSchema
feiler hvis rekkefølgen her og i C++ ikke er identisk.
"""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "feature_schema.json"


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


SCHEMA = load_schema()
FEATURES: list[str] = SCHEMA["features"]
SCHEMA_VERSION: int = SCHEMA["version"]
N_FEATURES = len(FEATURES)
ONNX_INPUT_NAME: str = SCHEMA["onnx"]["input_name"]
