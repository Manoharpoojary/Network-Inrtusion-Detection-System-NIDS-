"""Run predictions on validated frames and persist analyses, predictions and alerts."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

import pandas as pd
from sqlalchemy.orm import Session

from major_project.database.models import Alert, Analysis, Prediction
from major_project.services.explain import Explanation, ExplanationService
from major_project.services.inference import InferenceService
from major_project.services.inference import Prediction as ModelPrediction
from major_project.services.severity import ALERT_SEVERITIES, SeverityPolicy

logger = logging.getLogger(__name__)

_METADATA_COLUMNS = ("proto", "flgs", "sport", "dport", "pkts", "bytes", "dur")


@dataclass
class RecordedRow:
    row: Prediction
    result: ModelPrediction
    alert: Alert | None
    explanation: Explanation | None
    explanation_status: str


class PredictionRecorder:
    def __init__(
        self,
        inference: InferenceService,
        explainer: ExplanationService,
        policy: SeverityPolicy,
        max_eager_explanations: int,
    ):
        self.inference = inference
        self.explainer = explainer
        self.policy = policy
        self.max_eager_explanations = max_eager_explanations

    def start(
        self,
        session: Session,
        source: str,
        filename: str | None = None,
        ignored_columns: list[str] | None = None,
    ) -> Analysis:
        analysis = Analysis(
            source=source,
            filename=filename,
            status="running",
            created_at=datetime.now(UTC),
            model_version=self.inference.bundle.model_version,
            threshold=self.inference.attack_threshold,
            ignored_columns_json=json.dumps(ignored_columns) if ignored_columns else None,
        )
        session.add(analysis)
        session.flush()
        return analysis

    def record_chunk(
        self,
        session: Session,
        analysis: Analysis,
        frame: pd.DataFrame,
        start_index: int,
        explain: str,
        budget: list[int],
    ) -> list[RecordedRow]:
        """Predict and persist one validated chunk.

        ``explain``: "all" explains every row, "alerts" only alert rows, "none" nothing. ``budget``
        is a one-element list holding how many eager explanations remain for this analysis; rows
        beyond it are marked "deferred" (alerts are explained when first opened).
        """
        now = datetime.now(UTC)
        results = self.inference.predict_frame(frame)
        rows: list[RecordedRow] = []
        for offset, result in enumerate(results):
            raw = frame.iloc[offset]
            severity = self.policy.classify(result.is_attack, result.attack_probability)
            pred = Prediction(
                analysis_id=analysis.id,
                row_index=start_index + offset,
                created_at=now,
                label=result.label,
                attack_probability=result.attack_probability,
                severity=severity,
                model_version=result.model_version,
                **{c: _meta(raw[c]) for c in _METADATA_COLUMNS},
            )
            alert = None
            if severity in ALERT_SEVERITIES:
                alert = Alert(
                    analysis_id=analysis.id,
                    created_at=now,
                    severity=severity,
                    label=result.label,
                    attack_probability=result.attack_probability,
                    model_version=result.model_version,
                    proto=pred.proto,
                    dport=pred.dport,
                    features_json=json.dumps({k: _meta(v) for k, v in raw.items()}),
                )
                pred.alert = alert
            rows.append(RecordedRow(pred, result, alert, None, "not_requested"))
        session.add_all([r.row for r in rows])

        wanted = [
            i for i, r in enumerate(rows) if explain == "all" or (explain == "alerts" and r.alert)
        ]
        eager, deferred = wanted[: max(budget[0], 0)], wanted[max(budget[0], 0) :]
        if eager:
            explanations = self.explainer.explain_frame(frame.iloc[eager])
            for i, exp in zip(eager, explanations, strict=True):
                rows[i].explanation = exp
                rows[i].explanation_status = "included"
                if rows[i].alert is not None:
                    rows[i].alert.explanation_json = json.dumps(exp.as_dict())
            budget[0] -= len(eager)
        for i in deferred:
            rows[i].explanation_status = "deferred"

        analysis.total_records += len(rows)
        analysis.attack_count += sum(r.result.is_attack for r in rows)
        analysis.benign_count += sum(not r.result.is_attack for r in rows)
        analysis.alert_count += sum(r.alert is not None for r in rows)
        session.flush()
        return rows

    def finish(self, session: Session, analysis: Analysis) -> None:
        analysis.status = "completed"
        analysis.completed_at = datetime.now(UTC)
        session.flush()
        logger.info(
            "analysis completed",
            extra={
                "analysis_id": analysis.id,
                "source": analysis.source,
                "records": analysis.total_records,
                "alerts": analysis.alert_count,
            },
        )


def _meta(value):
    if isinstance(value, str):
        return value
    as_float = float(value)
    return int(as_float) if as_float.is_integer() else as_float
