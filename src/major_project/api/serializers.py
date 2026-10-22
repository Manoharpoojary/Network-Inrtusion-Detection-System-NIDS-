"""ORM / service objects → API response models."""

from __future__ import annotations

import json

from major_project.database.models import Alert, Analysis, Prediction
from major_project.schemas.api import (
    AlertOut,
    AnalysisOut,
    ExplanationOut,
    PredictionOut,
    PredictionRowOut,
    PredictionSummary,
    SeverityCounts,
)
from major_project.services.recording import RecordedRow


def analysis_out(a: Analysis) -> AnalysisOut:
    return AnalysisOut(
        id=a.id,
        source=a.source,
        filename=a.filename,
        status=a.status,
        created_at=a.created_at,
        completed_at=a.completed_at,
        total_records=a.total_records,
        benign_count=a.benign_count,
        attack_count=a.attack_count,
        alert_count=a.alert_count,
        model_version=a.model_version,
        threshold=a.threshold,
        ignored_columns=json.loads(a.ignored_columns_json) if a.ignored_columns_json else [],
    )


def summary_of(rows: list[RecordedRow]) -> PredictionSummary:
    attack = sum(r.result.is_attack for r in rows)
    return PredictionSummary(
        total=len(rows),
        benign=len(rows) - attack,
        attack=attack,
        alerts=SeverityCounts(
            medium=sum(r.row.severity == "medium" for r in rows),
            high=sum(r.row.severity == "high" for r in rows),
        ),
    )


def summary_of_analysis(a: Analysis, medium: int, high: int) -> PredictionSummary:
    return PredictionSummary(
        total=a.total_records,
        benign=a.benign_count,
        attack=a.attack_count,
        alerts=SeverityCounts(medium=medium, high=high),
    )


def prediction_out(r: RecordedRow) -> PredictionOut:
    res = r.result
    return PredictionOut(
        prediction_id=r.row.id,
        analysis_id=r.row.analysis_id,
        flow_index=r.row.row_index,
        label=res.label,
        label_id=res.label_id,
        is_attack=res.is_attack,
        attack_probability=res.attack_probability,
        benign_probability=res.benign_probability,
        threshold=res.threshold,
        severity=r.row.severity,
        alert_id=r.alert.id if r.alert else None,
        model_version=res.model_version,
        processed_at=r.row.created_at,
        warnings=list(res.warnings),
        explanation=ExplanationOut(**r.explanation.as_dict()) if r.explanation else None,
        explanation_status=r.explanation_status,
    )


def prediction_row_out(p: Prediction) -> PredictionRowOut:
    return PredictionRowOut(
        prediction_id=p.id,
        row_index=p.row_index,
        label=p.label,
        attack_probability=p.attack_probability,
        severity=p.severity,
        alert_id=p.alert.id if p.alert else None,
        proto=p.proto,
        flgs=p.flgs,
        sport=p.sport,
        dport=p.dport,
        pkts=p.pkts,
        bytes=p.bytes,
        dur=p.dur,
        processed_at=p.created_at,
    )


def alert_out(a: Alert) -> AlertOut:
    return AlertOut(
        id=a.id,
        analysis_id=a.analysis_id,
        prediction_id=a.prediction_id,
        flow_index=a.prediction.row_index,
        created_at=a.created_at,
        severity=a.severity,
        status=a.status,
        label=a.label,
        attack_probability=a.attack_probability,
        model_version=a.model_version,
        proto=a.proto,
        dport=a.dport,
        source=a.analysis.source,
        filename=a.analysis.filename,
    )
