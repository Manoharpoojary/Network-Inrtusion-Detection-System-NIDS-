"""Response (and non-feature request) models for the REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from major_project.schemas.flow import FlowFeatures

Severity = Literal["informational", "medium", "high"]
ExplanationStatus = Literal["included", "deferred", "not_requested", "unavailable"]


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: list[dict[str, Any]] | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail


class Page[T](BaseModel):
    items: list[T]
    total: int
    offset: int
    limit: int


# ----------------------------------------------------------------------------- explanations


class ContributionOut(BaseModel):
    feature: str
    value: float | str
    contribution: float = Field(description="Change in P(attack) attributed to this input")


class ExplanationOut(BaseModel):
    scope: Literal["local"]
    method: str
    method_description: str
    base_value: float = Field(description="Model's average P(attack) on the training data")
    attack_probability: float
    contributions: list[ContributionOut]
    other_contribution: float
    disclaimer: str


class GlobalImportanceOut(BaseModel):
    scope: Literal["global"] = "global"
    method: str = "Mean decrease in impurity (Random Forest feature_importances_)"
    note: str = "Describes the model as a whole. It does not explain any individual prediction."
    features: list[dict[str, float | str]]


# ----------------------------------------------------------------------------- predictions


class PredictionOut(BaseModel):
    prediction_id: int
    analysis_id: str
    flow_index: int
    label: Literal["Benign", "Attack"]
    label_id: int
    is_attack: bool
    attack_probability: float = Field(
        description="Fraction of trees voting attack. An uncalibrated model estimate."
    )
    benign_probability: float
    threshold: float
    severity: Severity
    alert_id: int | None
    model_version: str
    processed_at: datetime
    warnings: list[str]
    explanation: ExplanationOut | None
    explanation_status: ExplanationStatus


class BatchRequest(BaseModel):
    records: list[FlowFeatures] = Field(min_length=1, max_length=10_000)


class SeverityCounts(BaseModel):
    medium: int = 0
    high: int = 0


class PredictionSummary(BaseModel):
    total: int
    benign: int
    attack: int
    alerts: SeverityCounts


class BatchResponse(BaseModel):
    analysis_id: str
    model_version: str
    threshold: float
    summary: PredictionSummary
    predictions: list[PredictionOut]


class AnalysisOut(BaseModel):
    id: str
    source: str
    filename: str | None
    status: str
    created_at: datetime
    completed_at: datetime | None
    total_records: int
    benign_count: int
    attack_count: int
    alert_count: int
    model_version: str
    threshold: float
    ignored_columns: list[str]


class PredictionRowOut(BaseModel):
    prediction_id: int
    row_index: int
    label: str
    attack_probability: float
    severity: str
    alert_id: int | None
    proto: str | None
    flgs: str | None
    sport: int | None
    dport: int | None
    pkts: float | None
    bytes: float | None
    dur: float | None
    processed_at: datetime


class CsvAnalysisResponse(BaseModel):
    analysis: AnalysisOut
    summary: PredictionSummary
    predictions: list[PredictionRowOut] = Field(description="First page of results")
    predictions_truncated: bool
    results_url: str
    export_url: str


# ----------------------------------------------------------------------------- alerts


class AlertOut(BaseModel):
    id: int
    analysis_id: str
    prediction_id: int
    flow_index: int
    created_at: datetime
    severity: Severity
    status: str
    label: str
    attack_probability: float
    model_version: str
    proto: str | None
    dport: int | None
    source: str
    filename: str | None


class AlertDetailOut(AlertOut):
    features: dict[str, float | str]
    explanation: ExplanationOut | None
    explanation_status: ExplanationStatus
    explanation_note: str | None = None


# ----------------------------------------------------------------------------- dashboard


class AlertTotals(BaseModel):
    total: int
    open: int
    by_severity: SeverityCounts


class DashboardSummary(BaseModel):
    scope: str
    total_processed: int
    benign: int
    attack: int
    attack_share: float | None = Field(
        description="Share of processed flows the model labelled Attack (not an accuracy metric)"
    )
    alerts: AlertTotals
    analyses: int
    by_source: dict[str, int]
    last_processed_at: datetime | None
    recent_alerts: list[AlertOut]


class TrendPoint(BaseModel):
    bucket_start: datetime
    benign: int
    attack: int
    alerts_medium: int
    alerts_high: int


class Trends(BaseModel):
    bucket: Literal["hour", "day"]
    since: datetime
    until: datetime
    note: str
    points: list[TrendPoint]


# ----------------------------------------------------------------------------- system


class ComponentStatus(BaseModel):
    ok: bool
    detail: str | None = None


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    time: datetime
    uptime_seconds: float
    model: dict[str, Any]
    database: ComponentStatus
    explanations: dict[str, Any]
    live_inference: dict[str, Any]


class FeatureSpec(BaseModel):
    position: int
    name: str
    kind: Literal["numeric", "categorical"]
    allowed_values: list[str] | None
    constant_in_training: bool
    note: str | None


class ModelInfoOut(BaseModel):
    model_type: str
    model_version: str
    artifact_file: str
    artifact_sha256: str
    sklearn_version: str
    n_estimators: int
    class_labels: dict[str, str]
    threshold: float
    severity_rules: dict[str, str]
    capabilities: dict[str, Any]
    limits: dict[str, int]
    features: list[FeatureSpec]
