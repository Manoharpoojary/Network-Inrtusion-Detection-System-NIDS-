"""Network interfaces, capture availability, offline PCAP analysis and compatibility reports.

Nothing here sends extracted flows to the model: the compatibility report's inference gate stays
closed unless the features are compatible AND live inference is explicitly enabled.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, File, Query, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from major_project.api.deps import get_session, get_state
from major_project.api.errors import ApiError
from major_project.api.security import require_capture_control, require_local_client
from major_project.api.state import AppState, persist_detections
from major_project.database.models import LiveDetection, NetworkRun
from major_project.schemas.api import ErrorResponse
from major_project.services import capture_diagnostics, compatibility, interfaces
from major_project.services.capture_service import CaptureError
from major_project.services.csv_analysis import safe_filename
from major_project.services.pcap_analysis import (
    CaptureLibraryUnavailableError,
    PcapRejectedError,
    analyze_capture,
)

router = APIRouter(prefix="/api/network", tags=["network"])
FLOW_SAMPLE = 100


# BPF filter syntax only (letters, digits, spaces, operators); passed to libpcap, never a shell.
BPF_PATTERN = r"^[A-Za-z0-9 .:/()\[\]&|!<>=-]{1,200}$"


class LiveStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interface: str = Field(min_length=1, max_length=128)
    bpf_filter: str | None = Field(None, pattern=BPF_PATTERN)
    max_duration_seconds: int | None = Field(None, ge=1, le=3600)
    authorized: bool = Field(
        description="Must be true: you confirm you are authorised to monitor this interface."
    )
    detect: bool = Field(
        False, description="Score each finished flow with the live-adapted detection model"
    )


@router.get("/interfaces")
def list_interfaces() -> dict:
    """Interface names, state and counters (no IP/MAC addresses)."""
    return interfaces.discover_interfaces()


@router.post("/capture-check", responses={403: {"model": ErrorResponse}})
def capture_check(
    interface: str | None = Query(None, max_length=128),
    state: AppState = Depends(require_local_client),
) -> dict:
    """Open and immediately close one capture socket. No packets are read; nothing is stored."""
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
    report["predictions_note"] = "Not scored by the original dataset model: " + " ".join(
        report["inference_gate"]["reasons"]
    )

    run_id = str(uuid.uuid4())
    report["live_detection"] = _score_pcap(state, data, run_id)

    now = datetime.now(UTC)
    run = NetworkRun(
        id=run_id,
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


def _score_pcap(state: AppState, data: bytes, run_id: str) -> dict:
    """Score the capture's flows with the live model, using the live-detection flow timeouts."""
    if state.detector is None:
        return {"available": False, "reason": state.live_model_error or "Live model not loaded."}
    s = state.settings
    flows, _ = analyze_capture(
        data,
        max_packets=s.max_pcap_packets,
        max_flows_analyzed=s.max_flows_analyzed,
        idle_timeout=s.live_flow_idle_timeout_seconds,
        active_timeout=s.live_flow_active_timeout_seconds,
        max_active_flows=s.max_active_flows,
    )
    detections = state.detector.score(flows)
    persist_detections(state.db, run_id, "pcap", detections, state.detector.live.version)
    anomalies = sum(d.label == "Anomaly" for d in detections)
    return {
        "available": True,
        "model_version": state.detector.live.version,
        "threshold": state.detector.threshold,
        "time_unit": state.detector.time_unit,
        "flows_scored": len(detections),
        "anomalies": anomalies,
        "normal": len(detections) - anomalies,
        "detections": [d.as_dict() for d in detections[:FLOW_SAMPLE]],
    }


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


# ----------------------------------------------------------------------------- live capture

_LIVE_ERRORS = {s: {"model": ErrorResponse} for s in (401, 403, 404, 409, 422, 503)}


def _capture_call(fn, *args, **kwargs) -> dict:
    try:
        return fn(*args, **kwargs)
    except CaptureError as exc:
        raise ApiError(exc.status_code, exc.code, exc.message) from exc


@router.get("/live/status", responses=_LIVE_ERRORS)
def live_status(state: AppState = Depends(require_local_client)) -> dict:
    """Current capture session: state, counters, queue, recent flows and compatibility."""
    return state.capture.status()


@router.post("/live/start", responses=_LIVE_ERRORS)
def live_start(body: LiveStartRequest, state: AppState = Depends(require_capture_control)) -> dict:
    """Start feature extraction on one interface. Flows are NOT scored by the model."""
    if not body.authorized:
        raise ApiError(
            422,
            "authorization_not_confirmed",
            "Confirm you are authorised to monitor this interface (authorized: true).",
        )
    return _capture_call(
        state.capture.start,
        body.interface,
        body.bpf_filter,
        body.max_duration_seconds,
        body.detect,
    )


@router.post("/live/stop", responses=_LIVE_ERRORS)
def live_stop(state: AppState = Depends(require_capture_control)) -> dict:
    return _capture_call(state.capture.stop)


@router.post("/live/reset", responses=_LIVE_ERRORS)
def live_reset(state: AppState = Depends(require_capture_control)) -> dict:
    """Clear the finished session from the live panel. Saved runs in history are kept."""
    return _capture_call(state.capture.reset)


# ----------------------------------------------------------------------------- live detection


@router.get("/live/model")
def live_model_info(state: AppState = Depends(get_state)) -> dict:
    """The live-adapted detection model: features, classes, threshold and time unit."""
    if state.detector is None:
        return {"available": False, "error": state.live_model_error}
    return state.detector.info()


def _detection_out(d: LiveDetection) -> dict:
    return {
        "id": d.id,
        "run_id": d.run_id,
        "source": d.source,
        "detected_at": d.detected_at,
        "label": d.label,
        "anomaly_probability": d.anomaly_probability,
        "model_version": d.model_version,
        "protocol": d.protocol,
        "sport": d.sport,
        "dport": d.dport,
        "duration_s": d.duration_s,
        "fwd_pkts": d.fwd_pkts,
        "bwd_pkts": d.bwd_pkts,
        "fwd_bytes": d.fwd_bytes,
        "bwd_bytes": d.bwd_bytes,
        "features": json.loads(d.features_json),
    }


@router.get("/live/detections")
def list_detections(
    label: Literal["Anomaly", "Normal"] | None = None,
    source: Literal["live", "pcap"] | None = None,
    run_id: str | None = Query(None, max_length=36),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    session: Session = Depends(get_session),
) -> dict:
    """Stored live-model detections, newest first (ports and counts only; no addresses)."""
    stmt = select(LiveDetection)
    if label:
        stmt = stmt.where(LiveDetection.label == label)
    if source:
        stmt = stmt.where(LiveDetection.source == source)
    if run_id:
        stmt = stmt.where(LiveDetection.run_id == run_id)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.scalars(
        stmt.order_by(LiveDetection.detected_at.desc(), LiveDetection.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    counts = dict(
        session.execute(
            select(LiveDetection.label, func.count(LiveDetection.id)).group_by(LiveDetection.label)
        ).all()
    )
    return {
        "items": [_detection_out(d) for d in rows],
        "total": total,
        "offset": offset,
        "limit": limit,
        "totals": {"anomaly": counts.get("Anomaly", 0), "normal": counts.get("Normal", 0)},
    }
