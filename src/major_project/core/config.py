"""Application settings, read from environment variables (prefix ``NIDS_``) or a ``.env`` file."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent

# The trusted artifact produced by cell 33 of training/Untitled2.ipynb.
DEFAULT_MODEL_PATH = PACKAGE_DIR / "model" / "iot_intrusion_rf_pipeline (1).joblib"
DEFAULT_MODEL_SHA256 = "2557ad7b7b25f76f877f9048889d0de8b062672ea7743e380bcf3e5190173cde"
EVALUATION_DIR = PACKAGE_DIR / "evaluation"
DEFAULT_DATABASE_URL = f"sqlite:///{(PROJECT_ROOT / 'data' / 'nids.db').as_posix()}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NIDS_", env_file=".env", extra="ignore")

    model_path: Path = DEFAULT_MODEL_PATH
    # Loading is refused when the file hash differs. Set to an empty string to disable the check
    # (only do this for an artifact you trained yourself).
    model_sha256: str = DEFAULT_MODEL_SHA256

    # A flow is labelled "Attack" when P(attack) >= this value. 0.5 reproduces the reported
    # evaluation (notebook cell 54). sklearn's predict() instead sends exact 0.5 ties to Benign.
    attack_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    # Attack predictions with P(attack) >= this are "high" severity, the rest "medium".
    # Rule-based labels for triage; not calibrated risk.
    severity_high_min_probability: float = Field(default=0.8, ge=0.0, le=1.0)

    # Threads used by the Random Forest per prediction call. 1 avoids thread over-subscription
    # inside the web server; it does not change predictions.
    inference_n_jobs: int = 1

    max_batch_records: int = Field(default=1000, ge=1, le=10_000)
    max_upload_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    max_csv_rows: int = Field(default=50_000, ge=1)
    csv_chunk_rows: int = Field(default=1000, ge=1)

    # "auto" uses SHAP when the optional `explain` extra is installed, otherwise tree-path
    # contributions. "shap_tree" / "tree_path" force one method.
    explanation_method: str = "auto"
    explanation_top_k: int = Field(default=8, ge=1, le=35)
    # Alerts explained while a request is processed; the rest are explained when first opened.
    max_eager_explanations: int = Field(default=50, ge=0)

    database_url: str = DEFAULT_DATABASE_URL
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Live capture can be wired up, but inference on live flows stays off until the extracted
    # features are shown to match the training semantics (see docs/MODEL_CARD.md).
    live_inference_enabled: bool = False

    log_level: str = "INFO"

    @model_validator(mode="after")
    def _check_thresholds(self) -> "Settings":
        if self.severity_high_min_probability < self.attack_threshold:
            raise ValueError("severity_high_min_probability must be >= attack_threshold")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
