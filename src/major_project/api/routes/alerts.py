"""Alert listing and detail (with local explanation computed on first view if needed)."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from major_project.api.deps import get_session, get_state
from major_project.api.errors import ApiError
from major_project.api.serializers import alert_out
from major_project.api.state import AppState
from major_project.database import queries
from major_project.schemas.api import AlertDetailOut, AlertOut, ExplanationOut, Page

router = APIRouter(prefix="/api", tags=["alerts"])
logger = logging.getLogger(__name__)


@router.get("/alerts", response_model=Page[AlertOut])
def list_alerts(
    severity: Literal["medium", "high"] | None = None,
    status: Literal["open", "acknowledged", "dismissed"] | None = None,
    analysis_id: str | None = Query(None, max_length=36),
    proto: str | None = Query(None, max_length=8),
    q: str | None = Query(None, max_length=64, description="Search protocol, port, alert id"),
    since: datetime | None = None,
    until: datetime | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_session),
) -> Page[AlertOut]:
    filters = queries.AlertFilters(severity, status, analysis_id, proto, q, since, until)
    items, total = queries.list_alerts(session, filters, offset, limit)
    return Page(items=[alert_out(a) for a in items], total=total, offset=offset, limit=limit)


@router.get("/alerts/{alert_id}", response_model=AlertDetailOut)
def get_alert(
    alert_id: int,
    state: AppState = Depends(get_state),
    session: Session = Depends(get_session),
) -> AlertDetailOut:
    alert = queries.get_alert(session, alert_id)
    if alert is None:
        raise ApiError(404, "not_found", "Alert not found.")

    features = json.loads(alert.features_json)
    explanation, status, note = None, "included", None
    if alert.explanation_json:
        explanation = json.loads(alert.explanation_json)
    elif not state.model_ready:
        status, note = "unavailable", "The model is not loaded, so no explanation can be computed."
    elif alert.model_version != state.bundle.model_version:
        status, note = "unavailable", "This alert was produced by a different model version."
    else:
        frame = state.inference.validate_records([features])
        explanation = state.explainer.explain_frame(frame)[0].as_dict()
        alert.explanation_json = json.dumps(explanation)
        session.commit()

    base = alert_out(alert).model_dump()
    return AlertDetailOut(
        **base,
        features=features,
        explanation=ExplanationOut(**explanation) if explanation else None,
        explanation_status=status,
        explanation_note=note,
    )
