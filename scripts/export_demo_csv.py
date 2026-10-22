"""Export the notebook's held-out test rows as a CSV ready for the dashboard's CSV analysis.

Writes (git-ignored) files under data/demo/:

* heldout_test_features.csv: the 2,000 held-out rows, exactly the 35 model feature columns
* heldout_test_labels.csv:   row number and true label, kept separate so they are not uploaded

Only the held-out 20% split is exported, so demo predictions are never made on training rows.

    uv run python scripts/export_demo_csv.py
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from major_project.core.config import get_settings
from major_project.services.model_loader import load_model

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "src" / "major_project" / "training" / "iot_intrusion_predictions.csv"
OUT_DIR = ROOT / "data" / "demo"


def main() -> None:
    settings = get_settings()
    bundle = load_model(settings.model_path, settings.model_sha256)
    df = pd.read_csv(DATASET)
    _, test = train_test_split(df, test_size=0.20, random_state=42, stratify=df["attack"])
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    features = test[list(bundle.schema.feature_order)].reset_index(drop=True)
    features.to_csv(OUT_DIR / "heldout_test_features.csv", index=False)
    labels = pd.DataFrame(
        {"row_index": range(len(test)), "attack": test["attack"].to_numpy(),
         "category": test["category"].to_numpy()}
    )  # fmt: skip
    labels.to_csv(OUT_DIR / "heldout_test_labels.csv", index=False)
    print(f"wrote {len(features)} held-out rows to {OUT_DIR.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
