"""Live detection with the live-adapted Random Forest (19 packet-derived flow features).

This model is separate from the original dataset model. Its features (described in
``livedetection/description.txt``) follow CICFlowMeter/IoTID20 naming and can be measured from
real packets, so it can score flows built by ``flow_features.FlowAggregator``.

Feature definitions used here (the friend's extractor code was not provided, so these follow the
description plus the units implied by the model's split thresholds):

* Protocol: IP protocol number (6 TCP, 17 UDP, 1 ICMP).
* Src_Port / Dst_Port: ports of the endpoint that sent the first packet / its peer.
* Flow_Duration, Flow_IAT_Mean, Flow_IAT_Std: time between first and last packet, and the
  mean / sample standard deviation of inter-arrival times, in ``time_unit`` (default
  microseconds, the CICFlowMeter convention).
* Tot_Fwd_Pkts / Tot_Bwd_Pkts: packets from the initiator / from the responder.
* TotLen_Fwd_Pkts / TotLen_Bwd_Pkts, Pkt_Len_*: transport payload bytes (thresholds top out at
  1454 / 1472 = TCP / UDP payload maximum).
* *_Flag_Cnt: 1 if any packet in the flow carried the flag, else 0 (all splits are at 0.5).
"""

from __future__ import annotations

import logging
import math
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import InconsistentVersionWarning

from major_project.services.flow_features import IP_PROTO_NAMES, ExtractedFlow
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
TIME_SCALE = {"microseconds": 1e6, "milliseconds": 1e3, "seconds": 1.0}
_FLAG_LETTERS = {
    "SYN_Flag_Cnt": "S", "ACK_Flag_Cnt": "A", "RST_Flag_Cnt": "R", "FIN_Flag_Cnt": "F",
    "PSH_Flag_Cnt": "P",
}  # fmt: skip


def _sample_std(n: int, total: float, total_sq: float) -> float:
    if n < 2:
        return 0.0
    variance = (total_sq - total * total / n) / (n - 1)
    return math.sqrt(max(variance, 0.0))


def live_features(flow: ExtractedFlow, time_unit: str = "microseconds") -> dict[str, float]:
    """The 19 model inputs for one flow, in model order."""
    scale = TIME_SCALE[time_unit]
    n = flow.pkts
    iat_mean = flow.iat_sum / flow.iat_count if flow.iat_count else 0.0
    values = {
        "Protocol": float(flow.ip_proto),
        "Src_Port": float(flow.sport),
        "Dst_Port": float(flow.dport),
        "Flow_Duration": flow.dur * scale,
        "Tot_Fwd_Pkts": float(flow.spkts),
        "Tot_Bwd_Pkts": float(flow.dpkts),
        "TotLen_Fwd_Pkts": float(flow.fwd_payload),
        "TotLen_Bwd_Pkts": float(flow.bwd_payload),
        "Pkt_Len_Min": float(flow.payload_min),
        "Pkt_Len_Max": float(flow.payload_max),
        "Pkt_Len_Mean": flow.payload_sum / n if n else 0.0,
        "Pkt_Len_Std": _sample_std(n, flow.payload_sum, flow.payload_sum_sq),
        "Flow_IAT_Mean": iat_mean * scale,
        "Flow_IAT_Std": _sample_std(flow.iat_count, flow.iat_sum, flow.iat_sum_sq) * scale,
    }
    for name, letter in _FLAG_LETTERS.items():
        values[name] = 1.0 if letter in flow.tcp_flags else 0.0
    return {name: values[name] for name in LIVE_FEATURES}


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
    def __init__(self, live: LiveModel, threshold: float = 0.5, time_unit: str = "microseconds"):
        if time_unit not in TIME_SCALE:
            raise ValueError(f"time_unit must be one of {sorted(TIME_SCALE)}")
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be within [0, 1]")
        self.live = live
        self.threshold = threshold
        self.time_unit = time_unit

    def score(self, flows: Sequence[ExtractedFlow]) -> list[Detection]:
        if not flows:
            return []
        rows = [live_features(f, self.time_unit) for f in flows]
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
                    protocol=IP_PROTO_NAMES.get(flow.ip_proto, str(flow.ip_proto)),
                    sport=flow.sport,
                    dport=flow.dport,
                    first_seen=flow.first_seen,
                    duration_s=flow.dur,
                    fwd_pkts=flow.spkts,
                    bwd_pkts=flow.dpkts,
                    fwd_bytes=flow.fwd_payload,
                    bwd_bytes=flow.bwd_payload,
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
            "time_unit": self.time_unit,
            "global_importance": [{"feature": f, "importance": float(v)} for f, v in importance],
        }
