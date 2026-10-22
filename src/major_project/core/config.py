"""Application settings, read from environment variables (prefix ``NIDS_``) or a ``.env`` file."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent.parent

# The trusted artifact produced by cell 33 of training/Untitled2.ipynb.
DEFAULT_MODEL_PATH = PACKAGE_DIR / "model" / "iot_intrusion_rf_pipeline (1).joblib"
DEFAULT_MODEL_SHA256 = "2557ad7b7b25f76f877f9048889d0de8b062672ea7743e380bcf3e5190173cde"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NIDS_", env_file=".env", extra="ignore")

    model_path: Path = DEFAULT_MODEL_PATH
    # Loading is refused when the file hash differs. Set to an empty string to disable the check
    # (only do this for an artifact you trained yourself).
    model_sha256: str = DEFAULT_MODEL_SHA256

    # A flow is labelled "Attack" when P(attack) >= this value. 0.5 reproduces the reported
    # evaluation (notebook cell 54). sklearn's predict() instead sends exact 0.5 ties to Benign.
    attack_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    # Threads used by the Random Forest per prediction call. 1 avoids thread over-subscription
    # inside the web server; it does not change predictions.
    inference_n_jobs: int = 1

    max_batch_records: int = Field(default=1000, ge=1)

    # Live capture can be wired up, but inference on live flows stays off until the extracted
    # features are shown to match the training semantics (see docs/MODEL_CARD.md).
    live_inference_enabled: bool = False

    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
