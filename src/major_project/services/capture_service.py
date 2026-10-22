"""Controlled live capture: start / stop / status, bounded queue, clean shutdown.

Pipeline (one session at a time):

    Scapy AsyncSniffer thread --prn--> header parsing --> bounded queue --> worker thread
        --> FlowAggregator --> recent flows + compatibility report --> session persisted on stop

* Only header fields are parsed (``flow_features.packet_meta``); packets themselves are not kept,
  so payloads never enter the queue.
* When the queue is full the packet is counted in ``dropped_queue_full``, never silently lost.
* Extracted flows are NEVER sent to the model. The compatibility report's inference gate is shown
  for transparency; this module has no code path that calls the predictor.
* Sessions end on user stop, maximum duration, sniffer error, or application shutdown.
"""

from __future__ import annotations

import contextlib
import logging
import queue
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from major_project.services import compatibility
from major_project.services.capture_diagnostics import classify_capture_error
from major_project.services.flow_features import (
    ExtractedFlow,
    FlowAggregator,
    MalformedPacketError,
    PacketMeta,
    packet_meta,
)

logger = logging.getLogger(__name__)

CaptureState = Literal["stopped", "starting", "running", "stopping", "error"]


class CaptureError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class Sniffer(Protocol):
    running: bool
    exception: BaseException | None

    def start(self) -> None: ...
    def stop(self, join: bool = True) -> Any: ...


SnifferFactory = Callable[[Any, str | None, Callable[[Any], None]], Sniffer]
InterfaceResolver = Callable[[str], Any]


def scapy_sniffer_factory(
    iface: Any, bpf_filter: str | None, prn: Callable[[Any], None]
) -> Sniffer:
    try:
        from scapy.sendrecv import AsyncSniffer
    except ImportError as exc:
        raise CaptureError(
            503, "scapy_missing", "Scapy is not installed: uv sync --extra capture"
        ) from exc
    return AsyncSniffer(iface=iface, filter=bpf_filter, prn=prn, store=False)


def scapy_interface_resolver(name: str) -> Any:
    try:
        from scapy.all import conf
    except ImportError as exc:
        raise CaptureError(
            503, "scapy_missing", "Scapy is not installed: uv sync --extra capture"
        ) from exc
    for iface in conf.ifaces.values():
        if name in (getattr(iface, "name", None), getattr(iface, "network_name", None)):
            return iface
    raise CaptureError(404, "interface_not_found", f"Interface {name!r} is not visible to Scapy.")


@dataclass
class CaptureCounters:
    packets_seen: int = 0
    packets_queued: int = 0
    dropped_queue_full: int = 0
    ip_packets: int = 0
    non_ip_packets: int = 0
    malformed_packets: int = 0
    flows_emitted: int = 0
    flows_evicted_for_capacity: int = 0


@dataclass
class CaptureSession:
    id: str
    interface: str
    bpf_filter: str | None
    max_duration_seconds: int
    started_at: datetime
    stopped_at: datetime | None = None
    state: CaptureState = "starting"
    stop_reason: str | None = None
    error: dict[str, str] | None = None
    counters: CaptureCounters = field(default_factory=CaptureCounters)


@dataclass
class CaptureLimits:
    queue_size: int = 10_000
    max_duration_seconds: int = 600
    recent_flows: int = 200
    idle_timeout: float = 60.0
    active_timeout: float = 300.0
    max_active_flows: int = 50_000
    startup_grace_seconds: float = 0.5
    join_timeout_seconds: float = 10.0


class LiveCaptureManager:
    def __init__(
        self,
        limits: CaptureLimits,
        feature_order: list[str],
        reference: dict | None = None,
        validator: Any = None,  # InferenceService, used ONLY for schema validation
        live_inference_enabled: bool = False,
        sniffer_factory: SnifferFactory = scapy_sniffer_factory,
        interface_resolver: InterfaceResolver = scapy_interface_resolver,
        meta_fn: Callable[[Any], PacketMeta | None] = packet_meta,
        on_finish: Callable[[CaptureSession, dict], None] | None = None,
    ):
        self.limits = limits
        self.feature_order = feature_order
        self.reference = reference
        self.validator = validator
        self.live_inference_enabled = live_inference_enabled
        self.sniffer_factory = sniffer_factory
        self.interface_resolver = interface_resolver
        self.meta_fn = meta_fn
        self.on_finish = on_finish

        self._lock = threading.RLock()
        self._session: CaptureSession | None = None
        self._sniffer: Sniffer | None = None
        self._queue: queue.Queue[PacketMeta] | None = None
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._aggregator: FlowAggregator | None = None
        self._recent: deque[ExtractedFlow] = deque(maxlen=limits.recent_flows)
        self._last_report: dict | None = None

    # ------------------------------------------------------------------ public API

    @property
    def state(self) -> CaptureState:
        return self._session.state if self._session else "stopped"

    def start(
        self, interface: str, bpf_filter: str | None = None, max_duration: int | None = None
    ) -> dict:
        with self._lock:
            if self.state in ("starting", "running", "stopping"):
                raise CaptureError(409, "capture_busy", "A capture session is already active.")
            duration = min(max_duration or self.limits.max_duration_seconds,
                           self.limits.max_duration_seconds)  # fmt: skip
            iface = self.interface_resolver(interface)
            session = CaptureSession(
                id=str(uuid.uuid4()),
                interface=interface,
                bpf_filter=bpf_filter,
                max_duration_seconds=duration,
                started_at=datetime.now(UTC),
            )
            self._session = session
            self._queue = queue.Queue(maxsize=self.limits.queue_size)
            self._aggregator = FlowAggregator(
                self.limits.idle_timeout, self.limits.active_timeout, self.limits.max_active_flows
            )
            self._recent.clear()
            self._last_report = None
            self._stop_event.clear()

            try:
                self._sniffer = self.sniffer_factory(iface, bpf_filter, self._on_packet)
                self._sniffer.start()
            except CaptureError as exc:
                self._fail(exc.code, exc.message)
                raise
            except Exception as exc:
                code, message = classify_capture_error(exc)
                self._fail(code, message)
                raise CaptureError(503, code, message) from exc

            # The sniffer opens its socket in a background thread; failures appear there.
            deadline = time.monotonic() + self.limits.startup_grace_seconds
            while time.monotonic() < deadline:
                if self._sniffer.exception is not None:
                    break
                time.sleep(0.02)
            if self._sniffer.exception is not None:
                code, message = classify_capture_error(self._sniffer.exception)
                self._fail(code, message)
                raise CaptureError(503, code, message)

            session.state = "running"
            self._worker = threading.Thread(target=self._run, name="capture-worker", daemon=True)
            self._worker.start()
            logger.info("capture started", extra={"source": "live"})
            return self.status()

    def stop(self, reason: str = "user_request") -> dict:
        with self._lock:
            if self.state not in ("starting", "running"):
                raise CaptureError(409, "capture_not_running", "No capture session is running.")
            self._session.state = "stopping"
            self._session.stop_reason = reason
            self._stop_event.set()
            worker = self._worker
        if worker is not None:
            worker.join(self.limits.join_timeout_seconds)
            if worker.is_alive():
                with self._lock:
                    self._session.state = "error"
                    self._session.error = {
                        "code": "shutdown_timeout",
                        "message": "The capture worker did not stop in time.",
                    }
        return self.status()

    def shutdown(self) -> None:
        """Stop any active session (application shutdown)."""
        if self.state in ("starting", "running"):
            with contextlib.suppress(CaptureError):  # it may have stopped in the meantime
                self.stop("application_shutdown")

    def status(self, include_flows: int = 50) -> dict:
        with self._lock:
            s = self._session
            q = self._queue
            if s is None:
                return {
                    "state": "stopped",
                    "session": None,
                    "live_inference": self._gate_dict(compatible=False),
                }
            end = s.stopped_at or datetime.now(UTC)
            report = self._last_report if s.state not in ("running", "starting") else None
            if report is None and self._recent:
                report = self._report(list(self._recent))
            flows = list(self._recent)[-include_flows:]
            return {
                "state": s.state,
                "session": {
                    "id": s.id,
                    "interface": s.interface,
                    "bpf_filter": s.bpf_filter,
                    "started_at": s.started_at,
                    "stopped_at": s.stopped_at,
                    "elapsed_seconds": round((end - s.started_at).total_seconds(), 1),
                    "max_duration_seconds": s.max_duration_seconds,
                    "stop_reason": s.stop_reason,
                    "error": s.error,
                    "counters": asdict(s.counters),
                    "queue": {
                        "depth": q.qsize() if q is not None else 0,
                        "capacity": self.limits.queue_size,
                    },
                    "active_flows": self._aggregator.active_flows if self._aggregator else 0,
                },
                "recent_flows": [
                    {"observed": f.as_dict(), "model_features": compatibility.model_candidate(f)}
                    for f in flows
                ],
                "compatibility": None if report is None else {
                    k: report[k] for k in (
                        "compatible", "verdict", "flows_analyzed", "blocking_features",
                        "status_counts", "invariants", "schema_validation",
                    )
                },
                "predictions": None,
                "live_inference": self._gate_dict(
                    compatible=bool(report and report["compatible"])
                ),
            }  # fmt: skip

    # ------------------------------------------------------------------ internals

    def _gate_dict(self, compatible: bool) -> dict:
        gate = compatibility.evaluate_gate(compatible, self.live_inference_enabled)
        return {
            "enabled": False,
            "gate_allowed": gate.allowed,
            "reasons": list(gate.reasons),
            "note": "Extracted flows are not scored by the model.",
        }

    def _fail(self, code: str, message: str) -> None:
        s = self._session
        s.state = "error"
        s.error = {"code": code, "message": message}
        s.stopped_at = datetime.now(UTC)
        s.stop_reason = "error"
        self._persist(s, None)

    def _on_packet(self, pkt: Any) -> None:
        """Runs in the sniffer thread: parse headers, enqueue metadata, never block."""
        s = self._session
        c = s.counters
        c.packets_seen += 1
        try:
            meta = self.meta_fn(pkt)
        except MalformedPacketError:
            c.malformed_packets += 1
            return
        except Exception:
            c.malformed_packets += 1
            return
        if meta is None:
            c.non_ip_packets += 1
            return
        c.ip_packets += 1
        try:
            self._queue.put_nowait(meta)
            c.packets_queued += 1
        except queue.Full:
            c.dropped_queue_full += 1

    def _emit(self, flows: list[ExtractedFlow]) -> None:
        if flows:
            self._session.counters.flows_emitted += len(flows)
            self._recent.extend(flows)

    def _run(self) -> None:
        s = self._session
        started = time.monotonic()
        last_expiry = started
        try:
            while not self._stop_event.is_set():
                try:
                    meta = self._queue.get(timeout=0.2)
                    self._emit(self._aggregator.add(meta))
                except queue.Empty:
                    pass
                now = time.monotonic()
                if now - last_expiry >= 1.0:
                    self._emit(self._aggregator.expire(time.time()))
                    last_expiry = now
                if self._sniffer.exception is not None:
                    code, message = classify_capture_error(self._sniffer.exception)
                    s.error = {"code": code, "message": message}
                    s.stop_reason = "sniffer_error"
                    break
                if now - started >= s.max_duration_seconds:
                    s.stop_reason = "max_duration"
                    break
        except Exception as exc:  # unexpected worker failure: stop cleanly and report it
            logger.error("capture worker failed", exc_info=exc)
            s.error = {"code": "worker_error", "message": type(exc).__name__}
            s.stop_reason = "worker_error"
        finally:
            self._finish()

    def _finish(self) -> None:
        s = self._session
        try:
            if self._sniffer is not None and getattr(self._sniffer, "running", False):
                self._sniffer.stop(join=True)
        except Exception as exc:  # stopping a failed sniffer can re-raise its error
            if s.error is None:
                code, message = classify_capture_error(exc)
                s.error = {"code": code, "message": message}
        # Drain what was already queued, then close every open flow.
        while True:
            try:
                self._emit(self._aggregator.add(self._queue.get_nowait()))
            except queue.Empty:
                break
        self._emit(self._aggregator.flush("capture_stopped"))
        s.counters.flows_evicted_for_capacity = self._aggregator.evicted_for_capacity
        report = self._report(list(self._recent)) if self._recent else None
        with self._lock:
            self._last_report = report
            s.stopped_at = datetime.now(UTC)
            s.state = "error" if s.error else "stopped"
            s.stop_reason = s.stop_reason or "user_request"
        self._persist(s, report)
        logger.info("capture stopped", extra={"records": s.counters.packets_seen})

    def _report(self, flows: list[ExtractedFlow]) -> dict:
        return compatibility.build_report(
            flows, self.feature_order, self.reference, self.validator, self.live_inference_enabled
        )

    def _persist(self, session: CaptureSession, report: dict | None) -> None:
        if self.on_finish is None:
            return
        try:
            self.on_finish(session, report or {})
        except Exception as exc:
            logger.error("could not persist capture session", exc_info=exc)
