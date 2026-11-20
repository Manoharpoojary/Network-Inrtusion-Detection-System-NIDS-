"""Live detection with the live-adapted Random Forest (19 packet-derived flow features).

This model is separate from the original dataset model. It was trained by
``train_live_adapted_model.py`` in https://github.com/prasadmogaveera/network-intrusion-detection-using-ml
on IoTID20-style flows plus live browsing flows produced by that project's
``flow_aggregator_v5.py``. Predictions are only meaningful for flows built the same way, so
``LiveFlowAggregator`` reproduces that aggregator exactly:

* TCP and UDP over IPv4 only; other packets are skipped.
* Flow key: (protocol, sorted endpoint pair). The first packet's sender is "forward" and its
  ports are Src_Port / Dst_Port.
* A flow ends when 0.1 s passes without a packet, when a packet arrives 0.1 s or more after the flow
  started (fixed 0.1 s window, matching training durations below 100,000 us), on a TCP RST
  (after counting that packet), or once FIN has been seen in both directions.
* Packet length = ``len(ip)`` (IP header + payload). Std = population standard deviation.
* Flow_Duration and inter-arrival times in microseconds; flags are 0/1 indicators.
"""

from __future__ import annotations

import logging
import math
import warnings
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import InconsistentVersionWarning

from major_project.services.flow_features import PacketMeta
from major_project.services.model_loader import (
    ArtifactIntegrityError,
    ModelLoadError,
    restricted_joblib_load,
    sha256_of,
)

logger = logging.getLogger(__name__)

LIVE_FEATURES: tuple[str, ...] = (
    "Protocol", "Src_Port", "Dst_Port", "Flow_Duration", "Tot_Fwd_Pkts", "Tot_Bwd_Pkts",
    "TotLen_Fwd_Pkts", "TotLen_Bwd_Pkts", "Pkt_Len_Min", "Pkt_Len_Max", "Pkt_Len_Mean",
    "Pkt_Len_Std", "Flow_IAT_Mean", "Flow_IAT_Std", "SYN_Flag_Cnt", "ACK_Flag_Cnt",
    "RST_Flag_Cnt", "FIN_Flag_Cnt", "PSH_Flag_Cnt",
)  # fmt: skip
ANOMALY, NORMAL = "Anomaly", "Normal"
FLOW_WINDOW_SECONDS = 0.1  # flow_aggregator_v5.FLOW_WINDOW_SECONDS (also its idle timeout)
_FLAGS = {"S": "SYN", "A": "ACK", "R": "RST", "F": "FIN", "P": "PSH"}
PROTO_NAMES = {6: "TCP", 17: "UDP"}


def _pstdev(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = sum(values) / len(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / len(values))


@dataclass
class LiveFlow:
    """One flow built exactly like flow_aggregator_v5. Addresses are kept only in memory."""

    protocol: int
    first_src: tuple[str, int]
    first_dst: tuple[str, int]
    start: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    lengths: list[int] = field(default_factory=list)
    times: list[float] = field(default_factory=list)
    flags: dict[str, int] = field(
        default_factory=lambda: {"SYN": 0, "ACK": 0, "RST": 0, "FIN": 0, "PSH": 0}
    )
    fin_directions: set[str] = field(default_factory=set)
    last_seen: float = 0.0

    @property
    def sport(self) -> int:
        return self.first_src[1]

    @property
    def dport(self) -> int:
        return self.first_dst[1]

    @property
    def duration_s(self) -> float:
        return max(self.times) - min(self.times) if self.times else 0.0

    def features(self) -> dict[str, float]:
        """The 19 model inputs in model order (v5 summarize + to_model_features)."""
        times = sorted(self.times)
        iats = [(times[i] - times[i - 1]) * 1_000_000 for i in range(1, len(times))]
        n = len(self.lengths)
        return {
            "Protocol": float(self.protocol),
            "Src_Port": float(self.sport),
            "Dst_Port": float(self.dport),
            "Flow_Duration": self.duration_s * 1_000_000,
            "Tot_Fwd_Pkts": float(self.fwd_packets),
            "Tot_Bwd_Pkts": float(self.bwd_packets),
            "TotLen_Fwd_Pkts": float(self.fwd_bytes),
            "TotLen_Bwd_Pkts": float(self.bwd_bytes),
            "Pkt_Len_Min": float(min(self.lengths)),
            "Pkt_Len_Max": float(max(self.lengths)),
            "Pkt_Len_Mean": sum(self.lengths) / n,
            "Pkt_Len_Std": _pstdev(self.lengths),
            "Flow_IAT_Mean": sum(iats) / len(iats) if iats else 0.0,
            "Flow_IAT_Std": _pstdev(iats),
            "SYN_Flag_Cnt": float(self.flags["SYN"]),
            "ACK_Flag_Cnt": float(self.flags["ACK"]),
            "RST_Flag_Cnt": float(self.flags["RST"]),
            "FIN_Flag_Cnt": float(self.flags["FIN"]),
            "PSH_Flag_Cnt": float(self.flags["PSH"]),
        }


class LiveFlowAggregator:
    """Port of flow_aggregator_v5.process_packet / finish_flow with a bounded flow table."""

    def __init__(self, window_seconds: float = FLOW_WINDOW_SECONDS, max_active: int = 50_000):
        if window_seconds <= 0 or max_active < 1:
            raise ValueError("window_seconds must be positive and max_active >= 1")
        self.window = window_seconds
        self.max_active = max_active
        self._flows: dict[tuple, LiveFlow] = {}
        self.evicted_for_capacity = 0
        self.skipped_packets = 0  # not TCP/UDP over IPv4

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    def _finish(self, key: tuple, done: list[LiveFlow]) -> None:
        flow = self._flows.pop(key, None)
        if flow is not None and flow.lengths:
            done.append(flow)

    def add(self, m: PacketMeta) -> list[LiveFlow]:
        done: list[LiveFlow] = []
        if m.ip_proto not in PROTO_NAMES or ":" in m.src:  # v5 handles IPv4 TCP/UDP only
            self.skipped_packets += 1
            return done
        src, dst, ts = (m.src, m.sport), (m.dst, m.dport), m.ts
        key = (m.ip_proto, tuple(sorted((src, dst))))

        for k in [k for k, f in self._flows.items() if ts - f.last_seen > self.window]:
            self._finish(k, done)
        if key in self._flows and ts - self._flows[key].start >= self.window:
            self._finish(key, done)
        if key not in self._flows:
            if len(self._flows) >= self.max_active:  # bound memory (not in v5)
                oldest = min(self._flows, key=lambda k: self._flows[k].last_seen)
                self._finish(oldest, done)
                self.evicted_for_capacity += 1
            self._flows[key] = LiveFlow(m.ip_proto, src, dst, ts, last_seen=ts)

        flow = self._flows[key]
        flow.start = min(flow.start, ts)
        flow.last_seen = max(flow.last_seen, ts)
        flow.lengths.append(m.ip_len)
        flow.times.append(ts)
        if src == flow.first_src and dst == flow.first_dst:
            direction = "forward"
            flow.fwd_packets += 1
            flow.fwd_bytes += m.ip_len
        else:
            direction = "backward"
            flow.bwd_packets += 1
            flow.bwd_bytes += m.ip_len

        if m.ip_proto == 6:
            for letter, name in _FLAGS.items():
                if letter in m.tcp_flags:
                    flow.flags[name] = 1
            if "R" in m.tcp_flags:
                self._finish(key, done)
            elif "F" in m.tcp_flags:
                flow.fin_directions.add(direction)
                if len(flow.fin_directions) == 2:
                    self._finish(key, done)
        return done

    def expire(self, now: float) -> list[LiveFlow]:
        """Finish flows idle for longer than the window (used when no packets arrive)."""
        done: list[LiveFlow] = []
        for k in [k for k, f in self._flows.items() if now - f.last_seen > self.window]:
            self._finish(k, done)
        return done

    def flush(self, reason: str = "end_of_input") -> list[LiveFlow]:
        done: list[LiveFlow] = []
        for k in list(self._flows):
            self._finish(k, done)
        return done


def extract_live_flows(metas: Iterable[PacketMeta]) -> list[LiveFlow]:
    agg = LiveFlowAggregator()
    flows: list[LiveFlow] = []
    for m in metas:
        flows.extend(agg.add(m))
    return flows + agg.flush()


@dataclass(frozen=True)
class LiveModel:
    model: RandomForestClassifier
    path: Path
    sha256: str
    pickled_sklearn_version: str | None
    anomaly_col: int

    @property
    def version(self) -> str:
        return f"rf-live-{self.sha256[:12]}"


def load_live_model(path: Path, expected_sha256: str | None) -> LiveModel:
    """Hash-check and load the live model with the restricted unpickler."""
    path = Path(path)
    if not path.is_file():
        raise ModelLoadError(f"Live model not found: {path.name}")
    digest = sha256_of(path)
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        raise ArtifactIntegrityError(f"SHA-256 mismatch for {path.name}: got {digest}")
    pickled_version = None
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", InconsistentVersionWarning)
            model = restricted_joblib_load(path)
        for w in caught:
            if w.category is InconsistentVersionWarning:
                pickled_version = getattr(w.message, "original_sklearn_version", None)
    except ModelLoadError:
        raise
    except Exception as exc:
        raise ModelLoadError(f"Could not load {path.name}: {type(exc).__name__}") from exc

    if not isinstance(model, RandomForestClassifier):
        raise ModelLoadError(
            f"Live model is {type(model).__name__}, expected RandomForestClassifier"
        )
    if tuple(getattr(model, "feature_names_in_", ())) != LIVE_FEATURES:
        raise ModelLoadError("Live model features do not match the 19 expected live features")
    classes = [str(c) for c in model.classes_]
    if sorted(classes) != sorted([ANOMALY, NORMAL]):
        raise ModelLoadError(f"Unexpected live model classes {classes}")
    model.n_jobs = 1
    return LiveModel(model, path, digest, pickled_version, classes.index(ANOMALY))


@dataclass(frozen=True)
class Detection:
    label: str
    anomaly_probability: float
    protocol: str
    sport: int
    dport: int
    first_seen: float
    duration_s: float
    fwd_pkts: int
    bwd_pkts: int
    fwd_bytes: int
    bwd_bytes: int
    features: dict[str, float]

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "anomaly_probability": self.anomaly_probability,
            "protocol": self.protocol,
            "sport": self.sport,
            "dport": self.dport,
            "first_seen": self.first_seen,
            "duration_s": self.duration_s,
            "fwd_pkts": self.fwd_pkts,
            "bwd_pkts": self.bwd_pkts,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "features": self.features,
        }


class LiveDetector:
    def __init__(self, live: LiveModel, threshold: float = 0.5):
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be within [0, 1]")
        self.live = live
        self.threshold = threshold

    def score(self, flows: Sequence[LiveFlow]) -> list[Detection]:
        if not flows:
            return []
        rows = [f.features() for f in flows]
        frame = pd.DataFrame(rows, columns=list(LIVE_FEATURES))
        probs = self.live.model.predict_proba(frame)[:, self.live.anomaly_col]
        if probs.shape != (len(flows),) or not np.all(np.isfinite(probs)):
            raise RuntimeError("live model returned an invalid probability array")
        out = []
        for flow, row, p in zip(flows, rows, probs, strict=True):
            p = float(p)
            out.append(
                Detection(
                    label=ANOMALY if p >= self.threshold else NORMAL,
                    anomaly_probability=p,
                    protocol=PROTO_NAMES.get(flow.protocol, str(flow.protocol)),
                    sport=flow.sport,
                    dport=flow.dport,
                    first_seen=flow.start,
                    duration_s=flow.duration_s,
                    fwd_pkts=flow.fwd_packets,
                    bwd_pkts=flow.bwd_packets,
                    fwd_bytes=flow.fwd_bytes,
                    bwd_bytes=flow.bwd_bytes,
                    features=row,
                )
            )
        return out

    def info(self) -> dict:
        m = self.live.model
        importance = sorted(
            zip(LIVE_FEATURES, m.feature_importances_, strict=True), key=lambda x: -x[1]
        )
        return {
            "available": True,
            "model_version": self.live.version,
            "artifact_file": self.live.path.name,
            "artifact_sha256": self.live.sha256,
            "pickled_sklearn_version": self.live.pickled_sklearn_version,
            "n_estimators": len(m.estimators_),
            "classes": [str(c) for c in m.classes_],
            "features": list(LIVE_FEATURES),
            "anomaly_threshold": self.threshold,
            "time_unit": "microseconds",
            "flow_window_seconds": FLOW_WINDOW_SECONDS,
            "extractor": "flow_aggregator_v5 (network-intrusion-detection-using-ml)",
            "global_importance": [{"feature": f, "importance": float(v)} for f, v in importance],
        }
