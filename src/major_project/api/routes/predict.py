"""Single and batch prediction on JSON flow records."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from major_project.api.deps import get_session, require_model
from major_project.api.errors import ApiError
from major_project.api.serializers import prediction_out, summary_of
from major_project.api.state import AppState
from major_project.schemas.api import BatchRequest, BatchResponse, ErrorResponse, PredictionOut
from major_project.schemas.flow import FlowFeatures

router = APIRouter(prefix="/api", tags=["predictions"])
_ERRORS = {422: {"model": ErrorResponse}, 503: {"model": ErrorResponse}}


@router.post("/predict", response_model=PredictionOut, responses=_ERRORS)
def predict_one(
    record: FlowFeatures,
    explain: bool = Query(True, description="Include a local explanation of this prediction"),
    state: AppState = Depends(require_model),
    session: Session = Depends(get_session),
) -> PredictionOut:
    frame = state.inference.validate_records([record.model_dump()])
    analysis = state.recorder.start(session, "api_single")
    rows = state.recorder.record_chunk(
        session, analysis, frame, 0, "all" if explain else "none", [1 if explain else 0]
    )
    state.recorder.finish(session, analysis)
    session.commit()
    return prediction_out(rows[0])


@router.post("/predict/batch", response_model=BatchResponse, responses=_ERRORS)
def predict_batch(
    body: BatchRequest,
    explain: str = Query(
        "alerts",
        pattern="^(none|alerts|all)$",
        description="Which predictions to explain now (bounded); remaining alerts are explained "
        "when opened",
    ),
    state: AppState = Depends(require_model),
    session: Session = Depends(get_session),
) -> BatchResponse:
    limit = state.settings.max_batch_records
    if len(body.records) > limit:
        raise ApiError(413, "batch_too_large", f"A batch may contain at most {limit} records.")
    frame = state.inference.validate_records([r.model_dump() for r in body.records])
    analysis = state.recorder.start(session, "api_batch")
    budget = [state.settings.max_eager_explanations]
    rows = state.recorder.record_chunk(session, analysis, frame, 0, explain, budget)
    state.recorder.finish(session, analysis)
    session.commit()
    return BatchResponse(
        analysis_id=analysis.id,
        model_version=analysis.model_version,
        threshold=analysis.threshold,
        summary=summary_of(rows),
        predictions=[prediction_out(r) for r in rows],
    )
