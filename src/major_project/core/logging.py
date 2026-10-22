"""JSON-lines application logging.

Only whitelisted ``extra`` fields are emitted, so request bodies, flow feature values and packet
content are never logged by accident.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

_EXTRA_FIELDS = (
    "method", "path", "status", "duration_ms", "analysis_id", "records", "alerts",
    "model_version", "features", "error_code", "source",
)  # fmt: skip


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in _EXTRA_FIELDS:
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger("major_project")
    root.setLevel(level.upper())
    if not any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        root.addHandler(handler)
    root.propagate = False
