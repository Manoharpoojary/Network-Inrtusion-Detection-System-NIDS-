"""Helpers for API tests: an app wired to a temporary SQLite database."""

from __future__ import annotations

import io
import json
from contextlib import contextmanager
from pathlib import Path

import pandas as pd
from fastapi.testclient import TestClient

from major_project.app import create_app
from major_project.core.config import Settings

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_flow_record.json"


def synthetic_record() -> dict:
    """SYNTHETIC record (tests/fixtures); for validation and plumbing tests only."""
    return dict(json.loads(FIXTURE.read_text(encoding="utf-8"))["record"])


def attackish(record: dict) -> dict:
    """A SYNTHETIC record the model scores as a high-probability attack."""
    return dict(record, pkts=95, spkts=47, dpkts=47, proto="TCP", dport=445, dur=0.2)


@contextmanager
def api_client(
    tmp_path: Path,
    raise_server_exceptions: bool = True,
    client_host: str = "testclient",
    **overrides,
):
    overrides.setdefault("log_level", "WARNING")
    settings = Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}", **overrides)
    app = create_app(settings)
    with TestClient(
        app, raise_server_exceptions=raise_server_exceptions, client=(client_host, 50000)
    ) as client:
        yield client


def csv_bytes(records: list[dict] | pd.DataFrame) -> bytes:
    frame = records if isinstance(records, pd.DataFrame) else pd.DataFrame(records)
    buffer = io.StringIO()
    frame.to_csv(buffer, index=False)
    return buffer.getvalue().encode("utf-8")


def upload(client: TestClient, data: bytes, name: str = "flows.csv", **params):
    return client.post("/api/analyze/csv", files={"file": (name, data, "text/csv")}, params=params)
