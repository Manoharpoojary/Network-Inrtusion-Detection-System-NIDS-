"""Compare features extracted from real packets with the model's training features.

Every model input has an explicit rule saying whether, and how, it can be produced from packets:

* ``derived``      same formula as in the training data (window/unit semantics still unverified)
* ``approximated`` heuristic (e.g. application label guessed from the port)
* ``incompatible`` the training definition cannot be reproduced from real packets
* ``not_computed`` constant in training; producing it would mean inventing a value

Values for ``incompatible`` and ``not_computed`` features are left as ``None``. They are never
filled in, so such records fail schema validation and cannot reach the model.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Literal

import numpy as np
import pandas as pd

from major_project.core.config import EVALUATION_DIR
from major_project.services.flow_features import ExtractedFlow
from major_project.services.inference import InferenceService, InputValidationError

FeatureStatus = Literal["derived", "approximated", "incompatible", "not_computed"]

# Application labels used in training, by destination port (from training_reference.json).
# Port 445 is labelled both "SMB" and "TCP" in training, so it is left ambiguous.
APP_PROTO_BY_PORT = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 1883: "MQTT", 5683: "CoAP", 123: "NTP", 554: "RTSP",
    139: "SMB", 1900: "SSDP",
}  # fmt: skip
TRANSPORT_OF_APP = {
    "HTTP": 6, "HTTPS": 6, "MQTT": 6, "RTSP": 6, "SMB": 6,
    "DNS": 17, "NTP": 17, "SSDP": 17, "CoAP": 17,
}  # fmt: skip


@dataclass(frozen=True)
class FeatureRule:
    feature: str
    status: FeatureStatus
    method: str
    reason: str


_AGGREGATES = (
    "TnBPSrcIP", "TnBPDstIP", "TnP_PSrcIP", "TnP_PDstIP", "TnP_PerProto", "TnP_Per_Dport",
    "AR_P_Proto_P_SrcIP", "AR_P_Proto_P_DstIP", "N_IN_Conn_P_DstIP", "N_IN_Conn_P_SrcIP",
    "AR_P_Proto_P_Sport", "AR_P_Proto_P_Dport", "Pkts_P_State_P_Protocol_P_DestIP",
    "Pkts_P_State_P_Protocol_P_SrcIP",
)  # fmt: skip
_WINDOW = "Formula matches the training data; the training flow window/timeout is unknown."
_SYMMETRIC = (
    "In training this always equals half the total (both directions identical). Real flows are "
    "asymmetric, so the measured value has a different meaning; copying total // 2 would be "
    "inventing data."
)

RULES: dict[str, FeatureRule] = {
    r.feature: r
    for r in [
        FeatureRule("flgs", "incompatible", "-",
                    "In training flgs is fixed by protocol (TCP->PA, UDP->U, ICMP->S), not taken "
                    "from observed flags."),
        FeatureRule("flgs_number", "not_computed", "-",
                    "Always 1 in training; its meaning is unknown and the model never uses it."),
        FeatureRule("proto", "approximated", "application label from destination port",
                    "Training labels map one-to-one to ports; port 445 and unknown ports are "
                    "ambiguous and left empty."),
        FeatureRule("proto_number", "derived", "IP protocol number", _WINDOW),
        FeatureRule("sport", "derived", "initiator's source port", _WINDOW),
        FeatureRule("dport", "derived", "initiator's destination port", _WINDOW),
        FeatureRule("pkts", "derived", "packets in both directions", _WINDOW),
        FeatureRule("bytes", "derived", "on-the-wire bytes in both directions",
                    _WINDOW + " Byte-counting convention (L2 vs L3) is not documented."),
        FeatureRule("dur", "derived", "last - first packet time (s)", _WINDOW),
        FeatureRule("mean", "derived", "bytes / pkts", "Training: mean == bytes / pkts."),
        FeatureRule("stddev", "incompatible", "-",
                    "Training values (0.10-1.50) are independent of packet-size spread; the "
                    "definition is unknown."),
        FeatureRule("sum", "derived", "bytes", "Training: sum == bytes."),
        FeatureRule("min", "incompatible", "-",
                    "In training, mean falls outside [min, max] for ~24% of rows, which is "
                    "impossible for packet sizes; the definition is unknown."),
        FeatureRule("max", "incompatible", "-", "Same as min."),
        FeatureRule("spkts", "incompatible", "-", _SYMMETRIC),
        FeatureRule("dpkts", "incompatible", "-", _SYMMETRIC),
        FeatureRule("sbytes", "incompatible", "-", _SYMMETRIC),
        FeatureRule("dbytes", "incompatible", "-", _SYMMETRIC),
        FeatureRule("rate", "derived", "bytes / dur (bytes per second)",
                    "Training: rate == bytes / dur. Undefined for zero-duration flows."),
        FeatureRule("srate", "incompatible", "-", _SYMMETRIC),
        FeatureRule("drate", "incompatible", "-", _SYMMETRIC),
        *[
            FeatureRule(name, "not_computed", "-",
                        "Always 1 in training (never used by the model). Real per-host/protocol "
                        "aggregates would differ; writing 1 would be inventing data.")
            for name in _AGGREGATES
        ],
    ]
}  # fmt: skip


def app_proto(flow: ExtractedFlow) -> str | None:
    if flow.ip_proto == 1:
        return "ICMP"
    label = APP_PROTO_BY_PORT.get(flow.dport)
    if label is None or TRANSPORT_OF_APP.get(label) != flow.ip_proto:
        return None
    return label


def model_candidate(flow: ExtractedFlow) -> dict[str, float | str | None]:
    """The 35 model inputs for this flow; ``None`` where no faithful value exists."""
    values: dict[str, float | str | None] = dict.fromkeys(RULES)
    values.update(
        proto=app_proto(flow),
        proto_number=float(flow.ip_proto),
        sport=float(flow.sport),
        dport=float(flow.dport),
        pkts=float(flow.pkts),
        bytes=float(flow.bytes),
        dur=flow.dur,
        mean=flow.bytes / flow.pkts,
        sum=float(flow.bytes),
        rate=flow.bytes / flow.dur if flow.dur > 0 else None,
    )
    return values


@dataclass(frozen=True)
class InferenceGate:
    allowed: bool
    reasons: tuple[str, ...]


def evaluate_gate(compatible: bool, live_inference_enabled: bool) -> InferenceGate:
    """Model scoring of extracted flows requires BOTH a passing report AND explicit enablement."""
    reasons = []
    if not compatible:
        reasons.append("Extracted features are not compatible with the training features.")
    if not live_inference_enabled:
        reasons.append("Live inference is disabled by configuration (NIDS_LIVE_INFERENCE_ENABLED).")
    return InferenceGate(allowed=not reasons, reasons=tuple(reasons))


def load_training_reference() -> dict | None:
    path = EVALUATION_DIR / "training_reference.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def _share(mask: np.ndarray) -> float | None:
    return float(mask.mean()) if mask.size else None


def build_report(
    flows: Sequence[ExtractedFlow],
    feature_order: Sequence[str],
    reference: dict | None,
    inference: InferenceService | None,
    live_inference_enabled: bool,
) -> dict:
    candidates = pd.DataFrame([model_candidate(f) for f in flows], columns=list(feature_order))
    n = len(candidates)

    features = []
    for name in feature_order:
        rule = RULES[name]
        entry = asdict(rule)
        entry["flows_with_value"] = int(candidates[name].notna().sum()) if n else 0
        ref = (reference or {}).get("features", {}).get(name)
        if ref and ref["kind"] == "numeric":
            entry["training_range_p01_p99"] = [ref["p01"], ref["p99"]]
            if rule.status == "derived" and n:
                vals = pd.to_numeric(candidates[name], errors="coerce").dropna().to_numpy()
                entry["share_within_training_range"] = _share(
                    (vals >= ref["min"]) & (vals <= ref["max"])
                )
        elif ref and rule.status == "approximated" and n:
            seen = candidates[name].dropna()
            entry["share_with_training_category"] = _share(
                seen.isin(list(ref["frequencies"])).to_numpy()
            )
        features.append(entry)

    blocking = [f["feature"] for f in features if f["status"] in ("incompatible", "not_computed")]

    # Do the measured flows satisfy the relationships that hold for every training row?
    inv_ref = (reference or {}).get("invariants", {})
    if flows:
        sp = np.array([f.spkts for f in flows])
        dp = np.array([f.dpkts for f in flows])
        sb = np.array([f.sbytes for f in flows])
        db = np.array([f.dbytes for f in flows])
        pk = np.array([f.pkts for f in flows])
        mean = np.array([f.mean_len for f in flows])
        mn = np.array([f.min_len for f in flows])
        mx = np.array([f.max_len for f in flows])
    measured = {
        "spkts_equals_dpkts": (lambda: sp == dp, "measured spkts == dpkts"),
        "spkts_is_half_pkts": (lambda: sp == pk // 2, "measured spkts == pkts // 2"),
        "sbytes_equals_dbytes": (lambda: sb == db, "measured sbytes == dbytes"),
        "mean_within_min_max": (
            lambda: (mn <= mean) & (mean <= mx),
            "mean packet size within [min, max] packet size",
        ),
    }
    invariants = [
        {
            "invariant": key,
            "rule": label,
            "training_share": inv_ref.get(key, {}).get("share"),
            "extracted_share": _share(fn()) if flows else None,
        }
        for key, (fn, label) in measured.items()
    ]

    schema = {"checked": False, "passed": False, "rows_checked": n, "errors_by_feature": {}}
    if inference is not None and n:
        schema["checked"] = True
        try:
            inference.validate_frame(candidates)
            schema["passed"] = True
        except InputValidationError as exc:
            schema["errors_by_feature"] = dict(Counter(e.field for e in exc.errors))
            schema["truncated"] = exc.truncated

    compatible = n > 0 and not blocking and schema["passed"]
    gate = evaluate_gate(compatible, live_inference_enabled)
    return {
        "compatible": compatible,
        "verdict": (
            "Compatible" if compatible else
            f"Not compatible: {len(blocking)} of {len(feature_order)} model inputs cannot be "
            "produced from packets with the training data's meaning."
        ),
        "flows_analyzed": n,
        "blocking_features": blocking,
        "status_counts": dict(Counter(f["status"] for f in features)),
        "features": features,
        "invariants": invariants,
        "schema_validation": schema,
        "inference_gate": {"allowed": gate.allowed, "reasons": list(gate.reasons)},
    }  # fmt: skip
