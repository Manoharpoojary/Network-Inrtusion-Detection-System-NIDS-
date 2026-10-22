"""Summarise the model's TRAINING split for feature-compatibility checks.

Writes ``src/major_project/evaluation/training_reference.json`` with, for each of the 35 inputs,
its range/quantiles (numeric) or category frequencies (categorical), plus the internal invariants
the training data satisfies (e.g. ``spkts == dpkts``). Uses only the 8,000 training rows of the
notebook's split; no individual rows are written.

    uv run python scripts/build_training_reference.py
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from major_project.core.config import get_settings
from major_project.services.model_loader import load_model

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "src" / "major_project" / "training" / "iot_intrusion_predictions.csv"
OUTPUT = ROOT / "src" / "major_project" / "evaluation" / "training_reference.json"


def invariants(X: pd.DataFrame) -> dict[str, dict]:
    """Relationships between columns, with the share of training rows that satisfy them."""
    checks = {
        "spkts_equals_dpkts": (X.spkts == X.dpkts, "spkts == dpkts"),
        "sbytes_equals_dbytes": (X.sbytes == X.dbytes, "sbytes == dbytes"),
        "spkts_is_half_pkts": (X.spkts == X.pkts // 2, "spkts == pkts // 2"),
        "sbytes_is_half_bytes": (X.sbytes == X.bytes // 2, "sbytes == bytes // 2"),
        "sum_equals_bytes": (X["sum"] == X.bytes, "sum == bytes"),
        "mean_is_bytes_per_packet": (
            np.isclose(X["mean"], X.bytes / X.pkts),
            "mean == bytes / pkts",
        ),
        "rate_is_bytes_per_second": (
            np.isclose(X.rate, X.bytes / X.dur, atol=0.01),
            "rate == bytes / dur",
        ),
        "srate_equals_drate": (X.srate == X.drate, "srate == drate"),
        "mean_within_min_max": (
            (X["min"] <= X["mean"]) & (X["mean"] <= X["max"]),
            "min <= mean <= max",
        ),
    }
    return {k: {"rule": rule, "share": float(mask.mean())} for k, (mask, rule) in checks.items()}


def main() -> None:
    settings = get_settings()
    bundle = load_model(settings.model_path, settings.model_sha256)
    df = pd.read_csv(DATASET)
    X = df[list(bundle.schema.feature_order)]
    X_train, _ = train_test_split(X, test_size=0.20, random_state=42, stratify=df["attack"])

    features = {}
    for name in bundle.schema.feature_order:
        col = X_train[name]
        if name in bundle.schema.categorical_features:
            features[name] = {
                "kind": "categorical",
                "frequencies": {str(k): int(v) for k, v in col.value_counts().items()},
            }
        else:
            q = col.quantile([0.01, 0.5, 0.99])
            features[name] = {
                "kind": "numeric",
                "min": float(col.min()),
                "p01": float(q[0.01]),
                "median": float(q[0.5]),
                "p99": float(q[0.99]),
                "max": float(col.max()),
                "constant": bool(col.nunique() == 1),
            }

    reference = {
        "generated_at": datetime.now(UTC).isoformat(),
        "description": "Training split (8,000 rows) of the notebook's 80/20 split. Summary only.",
        "model_sha256": bundle.sha256,
        "dataset_sha256": hashlib.sha256(DATASET.read_bytes()).hexdigest(),
        "rows": len(X_train),
        "features": features,
        "invariants": invariants(X_train),
        "flgs_by_proto": {
            p: sorted(g.unique().tolist()) for p, g in X_train.groupby("proto")["flgs"]
        },
        "dport_by_proto": {
            p: sorted(int(v) for v in g.unique()) for p, g in X_train.groupby("proto")["dport"]
        },
    }
    OUTPUT.write_text(json.dumps(reference, indent=2), encoding="utf-8")
    for k, v in reference["invariants"].items():
        print(f"{k:28s} {v['share'] * 100:6.2f}%  ({v['rule']})")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
