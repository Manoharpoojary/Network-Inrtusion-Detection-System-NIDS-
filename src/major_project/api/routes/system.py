"""Health, model information, global importance and verified performance."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends

from major_project.api.deps import get_state, require_model
from major_project.api.errors import ApiError
from major_project.api.state import AppState
from major_project.core.config import EVALUATION_DIR
from major_project.schemas.api import (
    ComponentStatus,
    FeatureSpec,
    GlobalImportanceOut,
    HealthOut,
    ModelInfoOut,
)
from major_project.services.explain import METHOD_DESCRIPTIONS
from major_project.services.model_loader import CLASS_LABELS

router = APIRouter(prefix="/api", tags=["system"])

LIVE_INFERENCE_STATUS = {
    "enabled": False,
    "reason": (
        "The model's training features cannot be derived from real traffic "
        "(e.g. spkts == dpkts == pkts // 2; impossible min/max/stddev). "
        "See docs/MODEL_CARD.md and docs/IMPLEMENTATION_PLAN.md section 7.5."
    ),
}


@router.get("/health", response_model=HealthOut)
def health(state: AppState = Depends(get_state)) -> HealthOut:
    db_ok, db_error = state.db.ping()
    model = {"loaded": state.model_ready, "error": state.model_error}
    if state.bundle is not None:
        model["model_version"] = state.bundle.model_version
    return HealthOut(
        status="ok" if db_ok and state.model_ready else "degraded",
        time=datetime.now(UTC),
        uptime_seconds=round(time.time() - state.started_at, 1),
        model=model,
        database=ComponentStatus(ok=db_ok, detail=db_error),
        explanations={
            "method": state.explainer.method if state.explainer else None,
            "description": METHOD_DESCRIPTIONS.get(state.explainer.method)
            if state.explainer
            else None,
        },
        live_inference=LIVE_INFERENCE_STATUS,
    )


@router.get("/model/info", response_model=ModelInfoOut)
def model_info(state: AppState = Depends(require_model)) -> ModelInfoOut:
    bundle, s = state.bundle, state.settings
    schema = bundle.schema
    features = [
        FeatureSpec(
            position=i,
            name=name,
            kind="categorical" if name in schema.categorical_features else "numeric",
            allowed_values=list(schema.categorical_features[name])
            if name in schema.categorical_features
            else None,
            constant_in_training=name in schema.constant_features,
            note="Always 1 in training data; never used by the model's splits."
            if name in schema.constant_features
            else None,
        )
        for i, name in enumerate(schema.feature_order)
    ]
    return ModelInfoOut(
        model_type="scikit-learn Pipeline(ColumnTransformer -> RandomForestClassifier)",
        model_version=bundle.model_version,
        artifact_file=bundle.path.name,
        artifact_sha256=bundle.sha256,
        sklearn_version=bundle.sklearn_version,
        n_estimators=bundle.n_estimators,
        class_labels={str(k): v for k, v in CLASS_LABELS.items()},
        threshold=s.attack_threshold,
        severity_rules=state.policy.describe(),
        capabilities={
            "binary_classification": True,
            "multiclass_attack_types": False,
            "predict_proba": True,
            "calibrated_probabilities": False,
            "local_explanations": state.explainer.method,
            "global_importance": True,
            "live_inference": False,
        },
        limits={
            "max_batch_records": s.max_batch_records,
            "max_upload_bytes": s.max_upload_bytes,
            "max_csv_rows": s.max_csv_rows,
        },
        features=features,
    )


@router.get("/model/importance", response_model=GlobalImportanceOut)
def global_importance(state: AppState = Depends(require_model)) -> GlobalImportanceOut:
    return GlobalImportanceOut(features=state.explainer.global_importance())


def _read_json(name: str) -> dict | None:
    path = EVALUATION_DIR / name
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@router.get("/model/performance")
def model_performance(state: AppState = Depends(get_state)) -> dict:
    """Offline test-set metrics. Not live operational statistics."""
    verified = _read_json("verified_metrics.json")
    if verified is None:
        raise ApiError(
            404,
            "metrics_not_generated",
            "verified_metrics.json is missing; run scripts/reproduce_evaluation.py.",
        )
    current = state.bundle.sha256 if state.bundle else None
    return {
        "scope": "offline_test_set",
        "note": (
            "Metrics from the held-out 20% split of the same labelled file (not an independent "
            "dataset and not live traffic)."
        ),
        "matches_loaded_model": current is not None and verified["model"]["sha256"] == current,
        "application_threshold": state.settings.attack_threshold,
        "verified": verified,
        "notebook_reported": _read_json("notebook_reported.json"),
    }
