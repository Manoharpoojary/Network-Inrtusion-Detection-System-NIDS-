"""Objects built once at start-up and shared by request handlers."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field

from major_project.core.config import Settings
from major_project.database.models import NetworkRun
from major_project.database.session import Database
from major_project.schemas.flow import schema_mismatches
from major_project.services import compatibility
from major_project.services.capture_service import CaptureLimits, LiveCaptureManager
from major_project.services.explain import ExplanationService
from major_project.services.inference import InferenceService
from major_project.services.model_loader import ModelBundle, ModelLoadError, load_model
from major_project.services.recording import PredictionRecorder
from major_project.services.severity import SeverityPolicy

logger = logging.getLogger(__name__)


@dataclass
class AppState:
    settings: Settings
    db: Database
    policy: SeverityPolicy
    started_at: float = field(default_factory=time.time)
    bundle: ModelBundle | None = None
    inference: InferenceService | None = None
    explainer: ExplanationService | None = None
    recorder: PredictionRecorder | None = None
    model_error: str | None = None
    capture: LiveCaptureManager | None = None

    @property
    def model_ready(self) -> bool:
        return self.recorder is not None


def build_state(settings: Settings) -> AppState:
    db = Database(settings.database_url)
    db.init_schema()
    state = AppState(
        settings=settings,
        db=db,
        policy=SeverityPolicy(settings.attack_threshold, settings.severity_high_min_probability),
    )
    try:
        bundle = load_model(settings.model_path, settings.model_sha256, settings.inference_n_jobs)
        problems = schema_mismatches(bundle.schema)
        if problems:
            raise ModelLoadError("API schema does not match the artifact: " + "; ".join(problems))
        state.bundle = bundle
        state.inference = InferenceService(bundle, settings.attack_threshold)
        state.explainer = ExplanationService(
            bundle, settings.explanation_method, settings.explanation_top_k
        )
        state.recorder = PredictionRecorder(
            state.inference, state.explainer, state.policy, settings.max_eager_explanations
        )
    except ModelLoadError as exc:
        state.model_error = str(exc)
        logger.error("model unavailable", extra={"error_code": type(exc).__name__})

    state.capture = LiveCaptureManager(
        CaptureLimits(
            queue_size=settings.capture_queue_size,
            max_duration_seconds=settings.capture_max_duration_seconds,
            recent_flows=settings.capture_recent_flows,
            idle_timeout=settings.flow_idle_timeout_seconds,
            active_timeout=settings.flow_active_timeout_seconds,
            max_active_flows=settings.max_active_flows,
        ),
        feature_order=list(
            state.bundle.schema.feature_order if state.bundle else compatibility.RULES
        ),
        reference=compatibility.load_training_reference(),
        validator=state.inference,
        live_inference_enabled=settings.live_inference_enabled,
        on_finish=lambda session, report: persist_live_session(db, session, report),
    )
    return state


def persist_live_session(db: Database, session, report: dict) -> None:
    """Store a finished live session: counters and compatibility report only, no addresses."""
    c = session.counters
    with db.session() as s:
        s.add(
            NetworkRun(
                id=session.id,
                kind="live",
                filename=None,
                status="error" if session.error else "completed",
                created_at=session.started_at,
                completed_at=session.stopped_at,
                packets_read=c.packets_seen,
                ip_packets=c.ip_packets,
                non_ip_packets=c.non_ip_packets,
                malformed_packets=c.malformed_packets,
                dropped_packets=c.dropped_queue_full,
                flows_extracted=c.flows_emitted,
                compatible=bool(report.get("compatible")),
                stats_json=json.dumps(
                    {
                        **asdict(c),
                        "interface": session.interface,
                        "bpf_filter": session.bpf_filter,
                        "stop_reason": session.stop_reason,
                        "error": session.error,
                        "max_duration_seconds": session.max_duration_seconds,
                    }
                ),
                report_json=json.dumps(report, default=str),
            )
        )
        s.commit()
