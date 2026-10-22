"""Read-side queries for alerts, analyses and dashboard aggregates (parameterised SQL)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import Select, case, func, or_, select
from sqlalchemy.orm import Session, joinedload

from major_project.database.models import Alert, Analysis, Prediction

MAX_TREND_BUCKETS = 500


@dataclass
class AlertFilters:
    severity: str | None = None
    status: str | None = None
    analysis_id: str | None = None
    proto: str | None = None
    q: str | None = None
    since: datetime | None = None
    until: datetime | None = None


def _alert_query(filters: AlertFilters) -> Select:
    stmt = select(Alert)
    if filters.severity:
        stmt = stmt.where(Alert.severity == filters.severity)
    if filters.status:
        stmt = stmt.where(Alert.status == filters.status)
    if filters.analysis_id:
        stmt = stmt.where(Alert.analysis_id == filters.analysis_id)
    if filters.proto:
        stmt = stmt.where(Alert.proto == filters.proto)
    if filters.since:
        stmt = stmt.where(Alert.created_at >= filters.since)
    if filters.until:
        stmt = stmt.where(Alert.created_at < filters.until)
    if filters.q:
        term = filters.q.strip()
        clauses = [Alert.proto.ilike(f"%{term}%"), Alert.analysis_id.startswith(term)]
        if term.isdigit():
            clauses += [Alert.dport == int(term), Alert.id == int(term)]
        stmt = stmt.where(or_(*clauses))
    return stmt


def list_alerts(
    session: Session, filters: AlertFilters, offset: int, limit: int
) -> tuple[list[Alert], int]:
    base = _alert_query(filters)
    total = session.scalar(select(func.count()).select_from(base.subquery())) or 0
    items = session.scalars(
        base.options(joinedload(Alert.analysis), joinedload(Alert.prediction))
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return list(items), total


def get_alert(session: Session, alert_id: int) -> Alert | None:
    return session.scalar(
        select(Alert)
        .where(Alert.id == alert_id)
        .options(joinedload(Alert.analysis), joinedload(Alert.prediction))
    )


def list_analyses(session: Session, offset: int, limit: int) -> tuple[list[Analysis], int]:
    total = session.scalar(select(func.count(Analysis.id))) or 0
    items = session.scalars(
        select(Analysis).order_by(Analysis.created_at.desc()).offset(offset).limit(limit)
    ).all()
    return list(items), total


def _prediction_query(analysis_id: str, label: str | None) -> Select:
    stmt = select(Prediction).where(Prediction.analysis_id == analysis_id)
    if label:
        stmt = stmt.where(Prediction.label == label)
    return stmt


def list_predictions(
    session: Session, analysis_id: str, label: str | None, offset: int, limit: int
) -> tuple[list[Prediction], int]:
    base = _prediction_query(analysis_id, label)
    total = session.scalar(select(func.count()).select_from(base.subquery())) or 0
    items = session.scalars(
        base.options(joinedload(Prediction.alert))
        .order_by(Prediction.row_index)
        .offset(offset)
        .limit(limit)
    ).all()
    return list(items), total


def iter_predictions(session: Session, analysis_id: str, label: str | None) -> Iterator[Prediction]:
    stmt = (
        _prediction_query(analysis_id, label)
        .options(joinedload(Prediction.alert))
        .order_by(Prediction.row_index)
        .execution_options(yield_per=1000)
    )
    yield from session.scalars(stmt)


def summary_counts(session: Session) -> dict:
    total, attack, last = session.execute(
        select(
            func.count(Prediction.id),
            func.coalesce(func.sum(case((Prediction.label == "Attack", 1), else_=0)), 0),
            func.max(Prediction.created_at),
        )
    ).one()
    by_severity = dict(
        session.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all()
    )
    open_alerts = session.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0
    by_source = dict(
        session.execute(
            select(Analysis.source, func.count(Prediction.id))
            .join(Prediction, Prediction.analysis_id == Analysis.id)
            .group_by(Analysis.source)
        ).all()
    )
    analyses = session.scalar(select(func.count(Analysis.id))) or 0
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return {
        "total": int(total),
        "attack": int(attack),
        "benign": int(total) - int(attack),
        "last": last,
        "alerts_by_severity": {k: int(v) for k, v in by_severity.items()},
        "open_alerts": int(open_alerts),
        "by_source": {k: int(v) for k, v in by_source.items()},
        "analyses": int(analyses),
    }


def _bucket_expr(column, bucket: str, is_sqlite: bool):
    if is_sqlite:
        fmt = "%Y-%m-%d %H:00:00" if bucket == "hour" else "%Y-%m-%d 00:00:00"
        return func.strftime(fmt, column)
    return func.date_trunc(bucket, column)


def _floor(ts: datetime, bucket: str) -> datetime:
    ts = ts.astimezone(UTC)
    return (
        ts.replace(minute=0, second=0, microsecond=0)
        if bucket == "hour"
        else ts.replace(hour=0, minute=0, second=0, microsecond=0)
    )


def _parse_bucket(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def trends(
    session: Session, bucket: str, since: datetime, until: datetime, is_sqlite: bool
) -> list[dict]:
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    start = _floor(since, bucket)
    if (until - start) / step > MAX_TREND_BUCKETS:
        raise ValueError(f"range spans more than {MAX_TREND_BUCKETS} {bucket} buckets")

    points: dict[datetime, dict] = {}
    cursor = start
    while cursor < until:
        points[cursor] = {"bucket_start": cursor, "benign": 0, "attack": 0, "alerts_medium": 0,
                          "alerts_high": 0}  # fmt: skip
        cursor += step

    p_bucket = _bucket_expr(Prediction.created_at, bucket, is_sqlite).label("b")
    for b, label, n in session.execute(
        select(p_bucket, Prediction.label, func.count(Prediction.id))
        .where(Prediction.created_at >= since, Prediction.created_at < until)
        .group_by(p_bucket, Prediction.label)
    ):
        key = _parse_bucket(b)
        if key in points:
            points[key]["attack" if label == "Attack" else "benign"] += int(n)

    a_bucket = _bucket_expr(Alert.created_at, bucket, is_sqlite).label("b")
    for b, severity, n in session.execute(
        select(a_bucket, Alert.severity, func.count(Alert.id))
        .where(Alert.created_at >= since, Alert.created_at < until)
        .group_by(a_bucket, Alert.severity)
    ):
        key = _parse_bucket(b)
        if key in points and severity in ("medium", "high"):
            points[key][f"alerts_{severity}"] += int(n)
    return list(points.values())
