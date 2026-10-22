"""Re-run the notebook's evaluation of the saved Random Forest pipeline.

Reproduces the split from ``training/Untitled2.ipynb`` (cell 14: drop label/identifier/leaking
columns, ``train_test_split(test_size=0.20, random_state=42, stratify=y)``), scores the *saved
artifact* on the 2,000-row test split and writes
``src/major_project/evaluation/verified_metrics.json``.

Nothing is retrained and no input file is modified.

    uv run python scripts/reproduce_evaluation.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split

from major_project.core.config import get_settings
from major_project.services.model_loader import load_model

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = ROOT / "src" / "major_project" / "training" / "iot_intrusion_predictions.csv"
DEFAULT_OUTPUT = ROOT / "src" / "major_project" / "evaluation" / "verified_metrics.json"

# Columns the notebook appended to the dataset after prediction; not part of the original data.
APPENDED_COLUMNS = ["Prediction", "Attack Probability (%)"]
# Notebook cell 14: target, label-derived, identifier/time and leaking columns.
DROPPED_COLUMNS = [
    "attack", "category", "subcategory",
    "pkSeqID", "stime", "ltime", "saddr", "daddr", "seq",
    "state", "state_number",
]  # fmt: skip


def _metrics(y_true: np.ndarray, y_pred: np.ndarray, prob: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "accuracy": accuracy_score(y_true, y_pred),
        "attack_precision": precision_score(y_true, y_pred),
        "attack_recall": recall_score(y_true, y_pred),
        "attack_f1": f1_score(y_true, y_pred),
        "benign_recall": tn / (tn + fp),
        "false_positive_rate": fp / (fp + tn),
        "roc_auc": roc_auc_score(y_true, prob),
        "average_precision": average_precision_score(y_true, prob),
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    settings = get_settings()
    bundle = load_model(settings.model_path, settings.model_sha256)
    pipeline = bundle.pipeline

    df = pd.read_csv(args.dataset).drop(columns=APPENDED_COLUMNS, errors="ignore")
    y = df["attack"].astype(int)
    X = df.drop(columns=DROPPED_COLUMNS)
    if list(X.columns) != list(bundle.schema.feature_order):
        raise SystemExit("Dataset columns do not match the model's feature order")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Evidence that the artifact was fitted on exactly this training split.
    scaler = pipeline.named_steps["preprocessor"].named_transformers_["numeric"]
    numeric = list(scaler.feature_names_in_)
    scaler_matches_train = bool(
        np.allclose(scaler.mean_, X_train[numeric].mean().to_numpy(), rtol=0, atol=1e-9)
        and np.allclose(scaler.var_, X_train[numeric].var(ddof=0).to_numpy(), rtol=1e-9)
    )

    prob = pipeline.predict_proba(X_test)[:, 1]
    y_true = y_test.to_numpy()
    pred_threshold = (prob >= 0.5).astype(int)
    pred_argmax = pipeline.predict(X_test)

    train_hashes = set(pd.util.hash_pandas_object(X_train, index=False))
    test_hashes = pd.util.hash_pandas_object(X_test, index=False)

    fpr, tpr, roc_thr = roc_curve(y_true, prob)
    prec, rec, pr_thr = precision_recall_curve(y_true, prob)

    result = {
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "verified",
        "description": (
            "Saved Random Forest pipeline re-evaluated on the notebook's held-out 20% split "
            "of the same 10,000-row labelled file. Offline test metrics, not live performance."
        ),
        "model": {
            "file": bundle.path.name,
            "sha256": bundle.sha256,
            "model_version": bundle.model_version,
            "sklearn_runtime": sklearn.__version__,
        },
        "dataset": {
            "file": args.dataset.name,
            "sha256": _sha256(args.dataset),
            "source": "Mendeley Data, DOI 10.17632/m8swht7tmn.1 (labelled IoT file)",
            "rows": len(df),
            "class_counts": {"benign": int((y == 0).sum()), "attack": int((y == 1).sum())},
        },
        "methodology": {
            "split": "train_test_split(test_size=0.20, random_state=42, stratify=attack)",
            "train_rows": len(X_train),
            "test_rows": len(X_test),
            "test_class_counts": {
                "benign": int((y_test == 0).sum()),
                "attack": int((y_test == 1).sum()),
            },
            "dropped_columns": DROPPED_COLUMNS,
            "independent_test_set": False,
            "note": (
                "Training and test rows come from the same file and capture; there is no "
                "separate held-out dataset."
            ),
        },
        "integrity_checks": {
            "feature_order_matches_model": True,
            "scaler_fitted_on_training_split_only": scaler_matches_train,
            "training_accuracy": accuracy_score(y_train, pipeline.predict(X_train)),
            "test_rows_identical_to_a_training_row": int(test_hashes.isin(train_hashes).sum()),
            "duplicate_feature_rows_in_dataset": int(X.duplicated().sum()),
            "exact_probability_ties_at_0_5": int((prob == 0.5).sum()),
        },
        "metrics": {
            "threshold_ge_0_5": _metrics(y_true, pred_threshold, prob),
            "sklearn_predict_argmax": _metrics(y_true, pred_argmax, prob),
        },
        "curves": {
            "roc": {
                "fpr": fpr.round(6).tolist(),
                "tpr": tpr.round(6).tolist(),
                "thresholds": np.clip(roc_thr, 0, 1).round(6).tolist(),
            },
            "precision_recall": {
                "precision": prec.round(6).tolist(),
                "recall": rec.round(6).tolist(),
                "thresholds": pr_thr.round(6).tolist(),
            },
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")

    for name, m in result["metrics"].items():
        cm = m["confusion_matrix"]
        print(
            f"{name:24s} TN={cm['tn']} FP={cm['fp']} FN={cm['fn']} TP={cm['tp']} "
            f"acc={m['accuracy']:.4f} P={m['attack_precision']:.4f} R={m['attack_recall']:.4f} "
            f"F1={m['attack_f1']:.4f} AUC={m['roc_auc']:.4f} AP={m['average_precision']:.4f}"
        )
    print("integrity:", json.dumps(result["integrity_checks"]))
    print(f"wrote {args.output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
