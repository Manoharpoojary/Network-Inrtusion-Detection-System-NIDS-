"""Operational statistics over flows processed by this application (not model accuracy)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from major_project.api.deps import get_session, get_state
from major_project.api.errors import ApiError
from major_project.api.serializers import alert_out
from major_project.api.state import AppState
from major_project.database import queries
from major_project.schemas.api import AlertTotals, DashboardSummary, SeverityCounts, Trends

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(session: Session = Depends(get_session)) -> DashboardSummary:
    c = queries.summary_counts(session)
    recent, _ = queries.list_alerts(session, queries.AlertFilters(), 0, 5)
    by_sev = c["alerts_by_severity"]
    return DashboardSummary(
        scope="Operational statistics over inputs processed by this application; "
        "not a measure of model accuracy.",
        total_processed=c["total"],
        benign=c["benign"],
        attack=c["attack"],
        attack_share=c["attack"] / c["total"] if c["total"] else None,
        alerts=AlertTotals(
            total=sum(by_sev.values()),
            open=c["open_alerts"],
            by_severity=SeverityCounts(medium=by_sev.get("medium", 0), high=by_sev.get("high", 0)),
        ),
        analyses=c["analyses"],
        by_source=c["by_source"],
        last_processed_at=c["last"],
        recent_alerts=[alert_out(a) for a in recent],
    )


@router.get("/trends", response_model=Trends)
def trends(
    bucket: Literal["hour", "day"] = "hour",
    since: datetime | None = None,
    until: datetime | None = None,
    state: AppState = Depends(get_state),
    session: Session = Depends(get_session),
) -> Trends:
    now = datetime.now(UTC)
    until = _aware(until) or now
    since = _aware(since) or until - (
        timedelta(hours=24) if bucket == "hour" else timedelta(days=30)
    )
    if since >= until:
        raise ApiError(422, "invalid_range", "'since' must be earlier than 'until'.")
    try:
        points = queries.trends(session, bucket, since, until, state.db.is_sqlite)
    except ValueError as exc:
        raise ApiError(422, "invalid_range", str(exc)) from exc
    return Trends(
        bucket=bucket,
        since=since,
        until=until,
        note="Counts by processing time (UTC), not by original flow capture time.",
        points=points,
    )


def _aware(ts: datetime | None) -> datetime | None:
    if ts is None:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
