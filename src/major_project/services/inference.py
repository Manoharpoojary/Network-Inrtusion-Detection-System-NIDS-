"""Validate flow-feature records against the model schema and run predictions."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from numbers import Real
from typing import Any

import numpy as np
import pandas as pd

from major_project.services.model_loader import ATTACK_CLASS, CLASS_LABELS, ModelBundle

PORT_FEATURES = ("sport", "dport")
MAX_PORT = 65535
# Stop collecting validation errors after this many so a bad 50k-row file can't produce a huge
# response.
MAX_REPORTED_ERRORS = 50
PREDICT_CHUNK_ROWS = 5000

# IANA protocol numbers observed for each `proto` value in the training data.
_PROTO_NUMBER_BY_PROTO = {
    "TCP": 6, "HTTP": 6, "HTTPS": 6, "MQTT": 6, "RTSP": 6, "SMB": 6,
    "DNS": 17, "NTP": 17, "SSDP": 17, "CoAP": 17,
    "ICMP": 1,
}  # fmt: skip


@dataclass(frozen=True)
class FieldError:
    message: str
    field: str | None = None
    row: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"row": self.row, "field": self.field, "message": self.message}


class InputValidationError(ValueError):
    """One or more records do not satisfy the model's input contract."""

    def __init__(self, errors: list[FieldError], truncated: bool = False):
        self.errors = errors
        self.truncated = truncated
        super().__init__(
            f"{len(errors)} validation error(s)" + (" (truncated)" if truncated else "")
        )


class _ErrorCollector:
    def __init__(self) -> None:
        self.errors: list[FieldError] = []
        self.truncated = False

    def add(self, message: str, field: str | None = None, row: int | None = None) -> None:
        if len(self.errors) >= MAX_REPORTED_ERRORS:
            self.truncated = True
            return
        self.errors.append(FieldError(message, field, row))

    def raise_if_any(self) -> None:
        if self.errors:
            raise InputValidationError(self.errors, self.truncated)


@dataclass(frozen=True)
class Prediction:
    label: str
    label_id: int
    is_attack: bool
    # Fraction of trees voting "attack": an uncalibrated model estimate, not a risk probability.
    attack_probability: float
    benign_probability: float
    threshold: float
    model_version: str
    warnings: tuple[str, ...] = field(default=())


class InferenceService:
    def __init__(self, bundle: ModelBundle, attack_threshold: float = 0.5):
        if not 0.0 <= attack_threshold <= 1.0:
            raise ValueError("attack_threshold must be within [0, 1]")
        self.bundle = bundle
        self.schema = bundle.schema
        self.attack_threshold = attack_threshold
        self._attack_col = list(bundle.classifier.classes_).index(ATTACK_CLASS)

    # ------------------------------------------------------------------ validation

    def _check_columns(
        self, columns: Sequence[str], errors: _ErrorCollector, row: int | None
    ) -> bool:
        expected = set(self.schema.feature_order)
        present = set(columns)
        for name in sorted(expected - present, key=self.schema.feature_order.index):
            errors.add("required feature is missing", name, row)
        for name in sorted(present - expected):
            errors.add("unexpected feature; the model does not accept it", name, row)
        return present == expected

    def validate_records(self, records: Sequence[Mapping[str, Any]]) -> pd.DataFrame:
        """Validate JSON-style records and return a DataFrame in the model's column order."""
        errors = _ErrorCollector()
        if not records:
            raise InputValidationError([FieldError("no records supplied")])

        for i, record in enumerate(records):
            if not isinstance(record, Mapping):
                errors.add("record must be an object of feature values", row=i)
                continue
            if not self._check_columns(list(record.keys()), errors, i):
                continue
            for name in self.schema.numeric_features:
                value = record[name]
                # bool is a subclass of int; reject it explicitly.
                if isinstance(value, bool) or not isinstance(value, Real):
                    errors.add("must be a number", name, i)
            for name in self.schema.categorical_features:
                if not isinstance(record[name], str):
                    errors.add("must be a string", name, i)
        errors.raise_if_any()

        frame = pd.DataFrame.from_records(list(records), columns=list(self.schema.feature_order))
        return self.validate_frame(frame)

    def validate_frame(self, frame: pd.DataFrame, row_offset: int = 0) -> pd.DataFrame:
        """Validate a DataFrame (e.g. a CSV chunk).

        ``row_offset`` is added to the 0-based row numbers in error reports.
        """
        errors = _ErrorCollector()
        if frame.empty:
            raise InputValidationError([FieldError("no records supplied")])
        if frame.columns.duplicated().any():
            for name in frame.columns[frame.columns.duplicated()].unique():
                errors.add("column appears more than once", str(name))
            errors.raise_if_any()
        if not self._check_columns([str(c) for c in frame.columns], errors, None):
            errors.raise_if_any()

        out = pd.DataFrame(index=frame.index)
        for name in self.schema.feature_order:
            column = frame[name]
            if name in self.schema.categorical_features:
                allowed = self.schema.categorical_features[name]
                as_text = column.astype("string")
                bad = column.isna() | ~as_text.isin(allowed)
                for pos in np.flatnonzero(bad.to_numpy()):
                    errors.add(
                        f"value {column.iloc[pos]!r} is not one of {list(allowed)}",
                        name,
                        row_offset + int(pos),
                    )
                out[name] = as_text.astype(object)
            else:
                if column.dtype == bool:
                    numeric = pd.Series(np.nan, index=column.index)
                else:
                    numeric = pd.to_numeric(column, errors="coerce").astype("float64")
                values = numeric.to_numpy()
                not_finite = ~np.isfinite(values)
                for pos in np.flatnonzero(not_finite):
                    raw = column.iloc[pos]
                    reason = "missing value" if _is_missing(raw) else "must be a finite number"
                    errors.add(reason, name, row_offset + int(pos))
                finite = np.where(not_finite, 0.0, values)
                for pos in np.flatnonzero(finite < 0):
                    errors.add("must not be negative", name, row_offset + int(pos))
                if name in PORT_FEATURES:
                    bad_port = (finite > MAX_PORT) | (finite != np.floor(finite))
                    for pos in np.flatnonzero(bad_port & ~not_finite):
                        errors.add(
                            f"must be an integer port in 0..{MAX_PORT}", name, row_offset + int(pos)
                        )
                out[name] = numeric
        errors.raise_if_any()
        return out[list(self.schema.feature_order)]

    def record_warnings(self, frame: pd.DataFrame) -> list[tuple[str, ...]]:
        """Per-row notes about values that are valid but unlike the training data."""
        notes: list[list[str]] = [[] for _ in range(len(frame))]
        for name, train_value in self.schema.constant_features.items():
            for pos in np.flatnonzero(frame[name].to_numpy() != train_value):
                notes[pos].append(
                    f"{name} was always {train_value:g} in training data "
                    "and has no effect on the prediction"
                )
        if "proto" in frame and "proto_number" in frame:
            expected = frame["proto"].map(_PROTO_NUMBER_BY_PROTO)
            mismatch = expected.notna() & (expected != frame["proto_number"])
            for pos in np.flatnonzero(mismatch.to_numpy()):
                notes[pos].append(
                    f"proto_number {frame['proto_number'].iloc[pos]:g} differs from the value "
                    f"seen in training for proto {frame['proto'].iloc[pos]} "
                    f"({int(expected.iloc[pos])})"
                )
        return [tuple(n) for n in notes]

    # ------------------------------------------------------------------ prediction

    def attack_probabilities(self, frame: pd.DataFrame) -> np.ndarray:
        """P(attack) for an already validated frame, computed in bounded chunks."""
        parts = [
            self.bundle.pipeline.predict_proba(frame.iloc[start : start + PREDICT_CHUNK_ROWS])[
                :, self._attack_col
            ]
            for start in range(0, len(frame), PREDICT_CHUNK_ROWS)
        ]
        probs = np.concatenate(parts) if parts else np.empty(0)
        if probs.shape != (len(frame),) or not np.all(np.isfinite(probs)):
            raise RuntimeError("model returned an invalid probability array")
        return probs

    def predict_frame(self, frame: pd.DataFrame) -> list[Prediction]:
        probs = self.attack_probabilities(frame)
        notes = self.record_warnings(frame)
        version = self.bundle.model_version
        results = []
        for p, warn in zip(probs, notes, strict=True):
            p = float(p)
            is_attack = p >= self.attack_threshold
            label_id = ATTACK_CLASS if is_attack else 1 - ATTACK_CLASS
            results.append(
                Prediction(
                    label=CLASS_LABELS[label_id],
                    label_id=label_id,
                    is_attack=is_attack,
                    attack_probability=p,
                    benign_probability=1.0 - p,
                    threshold=self.attack_threshold,
                    model_version=version,
                    warnings=warn,
                )
            )
        return results

    def predict_records(self, records: Sequence[Mapping[str, Any]]) -> list[Prediction]:
        return self.predict_frame(self.validate_records(records))


def _is_missing(value: Any) -> bool:
    if value is None or value is pd.NA:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    try:
        return math.isnan(value)
    except TypeError:
        return False
