"""CSV upload analysis and stored analysis results."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from typing import Literal

from fastapi import APIRouter, Depends, File, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from major_project.api.deps import get_session, get_state, require_model
from major_project.api.errors import ApiError
from major_project.api.serializers import analysis_out, prediction_row_out, summary_of_analysis
from major_project.api.state import AppState
from major_project.database import queries
from major_project.database.models import Alert, Analysis
from major_project.schemas.api import (
    AnalysisOut,
    CsvAnalysisResponse,
    ErrorResponse,
    Page,
    PredictionRowOut,
)
from major_project.services.csv_analysis import parse_and_validate, read_limited, safe_filename

router = APIRouter(prefix="/api", tags=["analyses"])
FIRST_PAGE = 100


def _severity_counts(session: Session, analysis_id: str) -> tuple[int, int]:
    counts = dict(
        session.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.analysis_id == analysis_id)
            .group_by(Alert.severity)
        ).all()
    )
    return counts.get("medium", 0), counts.get("high", 0)


@router.post(
    "/analyze/csv",
    response_model=CsvAnalysisResponse,
    responses={s: {"model": ErrorResponse} for s in (400, 413, 422, 503)},
)
def analyze_csv(
    file: UploadFile = File(..., description="CSV with exactly the 35 model feature columns"),
    ignore_extra_columns: bool = Query(
        False, description="Drop columns that are not model features instead of rejecting"
    ),
    state: AppState = Depends(require_model),
    session: Session = Depends(get_session),
) -> CsvAnalysisResponse:
    s = state.settings
    data = read_limited(file.file, s.max_upload_bytes)
    parsed = parse_and_validate(
        data, state.inference, s.max_csv_rows, s.csv_chunk_rows, ignore_extra_columns
    )
    del data
    analysis = state.recorder.start(
        session, "csv", safe_filename(file.filename), parsed.ignored_columns
    )
    budget = [s.max_eager_explanations]
    for start, frame in parsed.chunks:
        state.recorder.record_chunk(session, analysis, frame, start, "alerts", budget)
    state.recorder.finish(session, analysis)
    session.commit()

    first, total = queries.list_predictions(session, analysis.id, None, 0, FIRST_PAGE)
    medium, high = _severity_counts(session, analysis.id)
    return CsvAnalysisResponse(
        analysis=analysis_out(analysis),
        summary=summary_of_analysis(analysis, medium, high),
        predictions=[prediction_row_out(p) for p in first],
        predictions_truncated=total > len(first),
        results_url=f"/api/analyses/{analysis.id}/predictions",
        export_url=f"/api/analyses/{analysis.id}/export.csv",
    )


@router.get("/analyses", response_model=Page[AnalysisOut])
def list_analyses(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_session),
) -> Page[AnalysisOut]:
    items, total = queries.list_analyses(session, offset, limit)
    return Page(items=[analysis_out(a) for a in items], total=total, offset=offset, limit=limit)


def _get_analysis(session: Session, analysis_id: str) -> Analysis:
    analysis = session.get(Analysis, analysis_id)
    if analysis is None:
        raise ApiError(404, "not_found", "Analysis not found.")
    return analysis


@router.get("/analyses/{analysis_id}", response_model=AnalysisOut)
def get_analysis(analysis_id: str, session: Session = Depends(get_session)) -> AnalysisOut:
    return analysis_out(_get_analysis(session, analysis_id))


@router.get("/analyses/{analysis_id}/predictions", response_model=Page[PredictionRowOut])
def analysis_predictions(
    analysis_id: str,
    label: Literal["Benign", "Attack"] | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    session: Session = Depends(get_session),
) -> Page[PredictionRowOut]:
    _get_analysis(session, analysis_id)
    items, total = queries.list_predictions(session, analysis_id, label, offset, limit)
    return Page(
        items=[prediction_row_out(p) for p in items], total=total, offset=offset, limit=limit
    )


EXPORT_COLUMNS = [
    "row_index", "label", "attack_probability", "severity", "alert_id", "proto", "flgs",
    "sport", "dport", "pkts", "bytes", "dur", "model_version", "processed_at_utc",
]  # fmt: skip


@router.get("/analyses/{analysis_id}/export.csv")
def export_analysis(
    analysis_id: str,
    label: Literal["Benign", "Attack"] | None = None,
    state: AppState = Depends(get_state),
) -> StreamingResponse:
    with state.db.session() as session:
        _get_analysis(session, analysis_id)

    def rows() -> Iterator[str]:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(EXPORT_COLUMNS)
        with state.db.session() as session:
            for i, p in enumerate(queries.iter_predictions(session, analysis_id, label)):
                writer.writerow([
                    p.row_index, p.label, f"{p.attack_probability:.4f}", p.severity,
                    p.alert.id if p.alert else "", p.proto, p.flgs, p.sport, p.dport,
                    p.pkts, p.bytes, p.dur, p.model_version, p.created_at.isoformat(),
                ])  # fmt: skip
                if i % 500 == 0:
                    yield buffer.getvalue()
                    buffer.seek(0)
                    buffer.truncate()
        yield buffer.getvalue()

    return StreamingResponse(
        rows(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="analysis-{analysis_id[:8]}.csv"'},
    )
