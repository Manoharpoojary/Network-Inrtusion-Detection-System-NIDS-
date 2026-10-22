"""Objects built once at start-up and shared by request handlers."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from major_project.core.config import Settings
from major_project.database.session import Database
from major_project.schemas.flow import schema_mismatches
from major_project.services.explain import ExplanationService
from major_project.services.inference import InferenceService
from major_project.services.model_loader import ModelBundle, ModelLoadError, load_model
from major_project.services.recording import PredictionRecorder
from major_project.services.severity import SeverityPolicy

logger = logging.getLogger(__name__)


@dataclass
class AppState:
    settings: Settings
    db: Database
    policy: SeverityPolicy
    started_at: float = field(default_factory=time.time)
    bundle: ModelBundle | None = None
    inference: InferenceService | None = None
    explainer: ExplanationService | None = None
    recorder: PredictionRecorder | None = None
    model_error: str | None = None

    @property
    def model_ready(self) -> bool:
        return self.recorder is not None


def build_state(settings: Settings) -> AppState:
    db = Database(settings.database_url)
    db.init_schema()
    state = AppState(
        settings=settings,
        db=db,
        policy=SeverityPolicy(settings.attack_threshold, settings.severity_high_min_probability),
    )
    try:
        bundle = load_model(settings.model_path, settings.model_sha256, settings.inference_n_jobs)
        problems = schema_mismatches(bundle.schema)
        if problems:
            raise ModelLoadError("API schema does not match the artifact: " + "; ".join(problems))
        state.bundle = bundle
        state.inference = InferenceService(bundle, settings.attack_threshold)
        state.explainer = ExplanationService(
            bundle, settings.explanation_method, settings.explanation_top_k
        )
        state.recorder = PredictionRecorder(
            state.inference, state.explainer, state.policy, settings.max_eager_explanations
        )
    except ModelLoadError as exc:
        state.model_error = str(exc)
        logger.error("model unavailable", extra={"error_code": type(exc).__name__})
    return state
