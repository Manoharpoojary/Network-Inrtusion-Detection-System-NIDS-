import json
from pathlib import Path

import pandas as pd
import pytest

from major_project.core.config import DEFAULT_MODEL_PATH, DEFAULT_MODEL_SHA256
from major_project.services.inference import InferenceService
from major_project.services.model_loader import ModelBundle, load_model

FIXTURES = Path(__file__).parent / "fixtures"
DATASET = (
    Path(__file__).parent.parent
    / "src"
    / "major_project"
    / "training"
    / "iot_intrusion_predictions.csv"
)


@pytest.fixture(scope="session")
def bundle() -> ModelBundle:
    if not DEFAULT_MODEL_PATH.is_file():
        pytest.skip("trusted model artifact not present")
    return load_model(DEFAULT_MODEL_PATH, DEFAULT_MODEL_SHA256)


@pytest.fixture(scope="session")
def service(bundle: ModelBundle) -> InferenceService:
    return InferenceService(bundle, attack_threshold=0.5)


@pytest.fixture
def synthetic_record() -> dict:
    """A fresh copy of the SYNTHETIC validation fixture (safe to mutate)."""
    data = json.loads((FIXTURES / "synthetic_flow_record.json").read_text(encoding="utf-8"))
    return dict(data["record"])


@pytest.fixture(scope="session")
def dataset() -> pd.DataFrame:
    if not DATASET.is_file():
        pytest.skip("labelled dataset CSV not present")
    return pd.read_csv(DATASET)
