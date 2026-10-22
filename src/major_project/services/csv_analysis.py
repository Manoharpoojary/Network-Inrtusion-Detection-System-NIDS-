"""Read, bound and validate an uploaded CSV of flow features.

The whole file is validated (in chunks) before anything is predicted or stored, so a file is
either processed completely or rejected with row-level errors.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import BinaryIO

import pandas as pd

from major_project.services.inference import (
    MAX_REPORTED_ERRORS,
    FieldError,
    InferenceService,
    InputValidationError,
)


class CsvRejectedError(Exception):
    def __init__(self, status_code: int, code: str, message: str, errors=None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.errors: list[dict] = errors or []


@dataclass
class ParsedCsv:
    chunks: list[tuple[int, pd.DataFrame]]  # (start row, validated frame)
    rows: int
    ignored_columns: list[str]


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ ()-]+")


def safe_filename(name: str | None) -> str | None:
    """Display-only base name. Never used as a filesystem path."""
    if not name:
        return None
    base = PurePath(name.replace("\\", "/")).name
    cleaned = _SAFE_NAME.sub("_", base).strip()[:100]
    return cleaned or None


def read_limited(stream: BinaryIO, max_bytes: int) -> bytes:
    data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise CsvRejectedError(
            413, "upload_too_large", f"File exceeds the {max_bytes:,}-byte upload limit."
        )
    if not data.strip():
        raise CsvRejectedError(400, "empty_file", "The uploaded file is empty.")
    return data


def parse_and_validate(
    data: bytes,
    service: InferenceService,
    max_rows: int,
    chunk_rows: int,
    ignore_extra_columns: bool = False,
) -> ParsedCsv:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CsvRejectedError(400, "invalid_encoding", "The CSV must be UTF-8 encoded.") from exc

    header = next(csv.reader(io.StringIO(text)), [])
    header = [h.strip() for h in header]
    duplicates = sorted({h for h in header if header.count(h) > 1})
    if duplicates:
        errors = [
            {"row": None, "field": d, "message": "column appears more than once"}
            for d in duplicates
        ]
        raise CsvRejectedError(422, "invalid_columns", "Duplicate column names.", errors)

    try:
        frame = pd.read_csv(io.StringIO(text), dtype=str, skipinitialspace=True)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as exc:
        raise CsvRejectedError(400, "csv_parse_error", f"Could not parse CSV: {exc}") from exc
    frame.columns = [str(c).strip() for c in frame.columns]
    if frame.empty:
        raise CsvRejectedError(400, "empty_file", "The CSV has a header but no data rows.")
    if len(frame) > max_rows:
        raise CsvRejectedError(
            413, "too_many_rows", f"The CSV has {len(frame):,} rows; the limit is {max_rows:,}."
        )

    expected = list(service.schema.feature_order)
    missing = [c for c in expected if c not in frame.columns]
    extra = [c for c in frame.columns if c not in expected]
    column_errors = [
        {"row": None, "field": c, "message": "required feature is missing"} for c in missing
    ]
    if extra and not ignore_extra_columns:
        column_errors += [
            {
                "row": None,
                "field": c,
                "message": "unexpected column (use ignore_extra_columns=true to drop it)",
            }
            for c in extra
        ]
    if column_errors:
        raise CsvRejectedError(
            422, "invalid_columns", "CSV columns do not match the model schema.", column_errors
        )

    frame = frame[expected]
    chunks: list[tuple[int, pd.DataFrame]] = []
    errors: list[FieldError] = []
    truncated = False
    for start in range(0, len(frame), chunk_rows):
        part = frame.iloc[start : start + chunk_rows]
        try:
            chunks.append((start, service.validate_frame(part, row_offset=start)))
        except InputValidationError as exc:
            errors.extend(exc.errors)
            truncated = truncated or exc.truncated
            if len(errors) >= MAX_REPORTED_ERRORS:
                truncated = True
                break
    if errors:
        raise CsvRejectedError(
            422,
            "invalid_features",
            "Some rows do not satisfy the model's input contract"
            + (" (first errors shown)." if truncated else "."),
            [
                {**e.as_dict(), "csv_line": None if e.row is None else e.row + 2}
                for e in errors[:MAX_REPORTED_ERRORS]
            ],
        )
    return ParsedCsv(chunks=chunks, rows=len(frame), ignored_columns=extra)
