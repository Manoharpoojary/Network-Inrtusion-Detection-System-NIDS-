"""Network interfaces, capture availability, offline PCAP analysis and compatibility reports.

Nothing here sends extracted flows to the model: the compatibility report's inference gate stays
closed unless the features are compatible AND live inference is explicitly enabled.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from major_project.api.deps import get_session, get_state
from major_project.api.errors import ApiError
from major_project.api.state import AppState
from major_project.database.models import NetworkRun
from major_project.schemas.api import ErrorResponse
from major_project.services import capture_diagnostics, compatibility, interfaces
from major_project.services.csv_analysis import safe_filename
from major_project.services.pcap_analysis import (
    CaptureLibraryUnavailableError,
    PcapRejectedError,
    analyze_capture,
)

router = APIRouter(prefix="/api/network", tags=["network"])
FLOW_SAMPLE = 100


def _require_local(request: Request, state: AppState) -> None:
    host = request.client.host if request.client else None
    if host not in state.settings.local_control_hosts:
        raise ApiError(403, "local_only", "This operation is only allowed from this machine.")


@router.get("/interfaces")
def list_interfaces() -> dict:
    """Interface names, state and counters (no IP/MAC addresses)."""
    return interfaces.discover_interfaces()


@router.post("/capture-check", responses={403: {"model": ErrorResponse}})
def capture_check(
    request: Request,
    interface: str | None = Query(None, max_length=128),
    state: AppState = Depends(get_state),
) -> dict:
    """Open and immediately close one capture socket. No packets are read; nothing is stored."""
    _require_local(request, state)
    report = capture_diagnostics.run_diagnostics(interface=interface, check=True)
    return {
        "scapy": report.scapy.__dict__,
        "driver": None if report.driver is None else report.driver.__dict__,
        "capture_check": report.capture_check.__dict__,
        "live_inference": report.live_inference,
    }


@router.get("/feature-mapping")
def feature_mapping(state: AppState = Depends(get_state)) -> dict:
    """How each model input would be produced from packets, and the training invariants."""
    reference = compatibility.load_training_reference()
    order = state.bundle.schema.feature_order if state.bundle else list(compatibility.RULES)
    return {
        "features": [compatibility.RULES[name].__dict__ for name in order],
        "training_invariants": (reference or {}).get("invariants"),
        "flow_definition": {
            "key": "IP protocol + unordered endpoint pair; first sender is the source",
            "idle_timeout_seconds": state.settings.flow_idle_timeout_seconds,
            "active_timeout_seconds": state.settings.flow_active_timeout_seconds,
            "bytes": "on-the-wire packet length",
        },
    }


def _run_out(run: NetworkRun, include_report: bool) -> dict:
    out = {
        "id": run.id,
        "kind": run.kind,
        "filename": run.filename,
        "status": run.status,
        "created_at": run.created_at,
        "completed_at": run.completed_at,
        "packets_read": run.packets_read,
        "ip_packets": run.ip_packets,
        "non_ip_packets": run.non_ip_packets,
        "malformed_packets": run.malformed_packets,
        "dropped_packets": run.dropped_packets,
        "flows_extracted": run.flows_extracted,
        "compatible": run.compatible,
        "stats": json.loads(run.stats_json),
    }
    if include_report:
        out["report"] = json.loads(run.report_json)
    return out


@router.post(
    "/pcap",
    responses={s: {"model": ErrorResponse} for s in (400, 413, 503)},
)
def analyze_pcap(
    file: UploadFile = File(
        ..., description="PCAP or PCAPNG capture you are authorised to analyse"
    ),
    state: AppState = Depends(get_state),
    session: Session = Depends(get_session),
) -> dict:
    s = state.settings
    data = file.file.read(s.max_pcap_bytes + 1)
    if len(data) > s.max_pcap_bytes:
        raise ApiError(413, "upload_too_large", f"File exceeds {s.max_pcap_bytes:,} bytes.")
    try:
        flows, stats = analyze_capture(
            data,
            max_packets=s.max_pcap_packets,
            max_flows_analyzed=s.max_flows_analyzed,
            idle_timeout=s.flow_idle_timeout_seconds,
            active_timeout=s.flow_active_timeout_seconds,
            max_active_flows=s.max_active_flows,
        )
    except PcapRejectedError as exc:
        raise ApiError(exc.status_code, exc.code, exc.message) from exc
    except CaptureLibraryUnavailableError as exc:
        raise ApiError(503, "capture_unavailable", str(exc)) from exc
    finally:
        del data

    order = state.bundle.schema.feature_order if state.bundle else list(compatibility.RULES)
    report = compatibility.build_report(
        flows,
        order,
        compatibility.load_training_reference(),
        state.inference,
        state.settings.live_inference_enabled,
    )
    report["flow_sample"] = [
        {"observed": f.as_dict(), "model_features": compatibility.model_candidate(f)}
        for f in flows[:FLOW_SAMPLE]
    ]
    report["predictions"] = None
    report["predictions_note"] = (
        "Not scored: " + " ".join(report["inference_gate"]["reasons"])
        if not report["inference_gate"]["allowed"]
        else "Scoring of extracted flows is not implemented."
    )

    now = datetime.now(UTC)
    run = NetworkRun(
        kind="pcap",
        filename=safe_filename(file.filename),
        status="completed"
        if stats.read_error is None and not stats.truncated_records
        else "partial",
        created_at=now,
        completed_at=now,
        packets_read=stats.packets_read,
        ip_packets=stats.ip_packets,
        non_ip_packets=stats.non_ip_packets,
        malformed_packets=stats.malformed_packets,
        flows_extracted=stats.flows_extracted,
        compatible=report["compatible"],
        stats_json=json.dumps(stats.as_dict()),
        report_json=json.dumps(report, default=str),
    )
    session.add(run)
    session.commit()
    return _run_out(run, include_report=True)


@router.get("/runs")
def list_runs(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_session),
) -> dict:
    total = session.scalar(select(func.count(NetworkRun.id))) or 0
    runs = session.scalars(
        select(NetworkRun).order_by(NetworkRun.created_at.desc()).offset(offset).limit(limit)
    ).all()
    return {
        "items": [_run_out(r, include_report=False) for r in runs],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/runs/{run_id}")
def get_run(run_id: str, session: Session = Depends(get_session)) -> dict:
    run = session.get(NetworkRun, run_id)
    if run is None:
        raise ApiError(404, "not_found", "Network run not found.")
    return _run_out(run, include_report=True)
