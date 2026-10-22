"""The flow-feature request model: exactly the 35 inputs of the trained pipeline, in model order.

The field list mirrors the trusted artifact. ``schema_mismatches`` compares it with the loaded
model at start-up, and the API refuses to serve predictions if they differ.
"""

from __future__ import annotations

import typing
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from major_project.services.model_loader import FeatureSchema

NonNegative = Annotated[float, Field(ge=0, allow_inf_nan=False, strict=True)]
Port = Annotated[int, Field(ge=0, le=65535, strict=True)]
Flag = Literal["PA", "S", "U"]
Proto = Literal["CoAP", "DNS", "HTTP", "HTTPS", "ICMP", "MQTT", "NTP", "RTSP", "SMB", "SSDP", "TCP"]

# Synthetic example for the OpenAPI docs only (same values as tests/fixtures).
_EXAMPLE = {
    "flgs": "PA", "flgs_number": 1, "proto": "HTTP", "proto_number": 6, "sport": 42620,
    "dport": 80, "pkts": 30, "bytes": 1500, "dur": 1.2, "mean": 50.0, "stddev": 1.1, "sum": 1500,
    "min": 45, "max": 900, "spkts": 15, "dpkts": 15, "sbytes": 750, "dbytes": 750, "rate": 800.0,
    "srate": 400.0, "drate": 400.0, "TnBPSrcIP": 1, "TnBPDstIP": 1, "TnP_PSrcIP": 1,
    "TnP_PDstIP": 1, "TnP_PerProto": 1, "TnP_Per_Dport": 1, "AR_P_Proto_P_SrcIP": 1,
    "AR_P_Proto_P_DstIP": 1, "N_IN_Conn_P_DstIP": 1, "N_IN_Conn_P_SrcIP": 1,
    "AR_P_Proto_P_Sport": 1, "AR_P_Proto_P_Dport": 1, "Pkts_P_State_P_Protocol_P_DestIP": 1,
    "Pkts_P_State_P_Protocol_P_SrcIP": 1,
}  # fmt: skip


class FlowFeatures(BaseModel):
    """One flow record in the dataset's feature definitions (see docs/MODEL_CARD.md)."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"examples": [_EXAMPLE]})

    flgs: Flag
    flgs_number: NonNegative
    proto: Proto
    proto_number: NonNegative
    sport: Port
    dport: Port
    pkts: NonNegative
    bytes: NonNegative
    dur: NonNegative = Field(description="Flow duration in seconds")
    mean: NonNegative
    stddev: NonNegative
    sum: NonNegative
    min: NonNegative
    max: NonNegative
    spkts: NonNegative
    dpkts: NonNegative
    sbytes: NonNegative
    dbytes: NonNegative
    rate: NonNegative
    srate: NonNegative
    drate: NonNegative
    TnBPSrcIP: NonNegative
    TnBPDstIP: NonNegative
    TnP_PSrcIP: NonNegative
    TnP_PDstIP: NonNegative
    TnP_PerProto: NonNegative
    TnP_Per_Dport: NonNegative
    AR_P_Proto_P_SrcIP: NonNegative
    AR_P_Proto_P_DstIP: NonNegative
    N_IN_Conn_P_DstIP: NonNegative
    N_IN_Conn_P_SrcIP: NonNegative
    AR_P_Proto_P_Sport: NonNegative
    AR_P_Proto_P_Dport: NonNegative
    Pkts_P_State_P_Protocol_P_DestIP: NonNegative
    Pkts_P_State_P_Protocol_P_SrcIP: NonNegative


def schema_mismatches(schema: FeatureSchema) -> list[str]:
    """Differences between this request model and the loaded artifact (empty if identical)."""
    problems: list[str] = []
    fields = list(FlowFeatures.model_fields)
    if fields != list(schema.feature_order):
        problems.append("field order differs from the model's feature_names_in_")
    for name, allowed in schema.categorical_features.items():
        info = FlowFeatures.model_fields.get(name)
        choices = typing.get_args(info.annotation) if info else ()
        if tuple(choices) != tuple(allowed):
            problems.append(f"allowed values for {name!r} differ from the fitted encoder")
    return problems
