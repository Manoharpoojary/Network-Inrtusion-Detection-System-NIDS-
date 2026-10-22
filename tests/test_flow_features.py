"""Flow aggregation and compatibility rules on SYNTHETIC packet metadata (no Scapy, no network).

Addresses come from the reserved documentation ranges 192.0.2.0/24 and 198.51.100.0/24.
"""

import pytest

from major_project.services import compatibility
from major_project.services.compatibility import (
    RULES,
    app_proto,
    build_report,
    evaluate_gate,
    model_candidate,
)
from major_project.services.flow_features import FlowAggregator, PacketMeta

A, B, C = "192.0.2.10", "198.51.100.20", "192.0.2.30"


def pm(ts, src, dst, sport, dport, length=100, proto=6, flags=""):
    return PacketMeta(ts, src, dst, sport, dport, proto, length, flags)


def tcp_conversation(t0=0.0, client_pkts=3, server_pkts=2):
    pkts = [pm(t0, A, B, 40000, 80, 60, flags="S")]
    pkts += [pm(t0 + 0.1 * i, B, A, 80, 40000, 1500, flags="PA") for i in range(1, server_pkts + 1)]
    pkts += [pm(t0 + 0.5 + 0.1 * i, A, B, 40000, 80, 52, flags="A") for i in range(client_pkts - 1)]
    return pkts


def run(packets, **kw):
    agg = FlowAggregator(**kw)
    out = []
    for p in packets:
        out += agg.add(p)
    return out + agg.flush(), agg


# ----------------------------------------------------------------------------- aggregation


def test_bidirectional_flow_statistics():
    [flow], _ = run(tcp_conversation())
    assert (flow.sport, flow.dport, flow.ip_proto) == (40000, 80, 6)
    assert (flow.pkts, flow.spkts, flow.dpkts) == (5, 3, 2)
    assert (flow.sbytes, flow.dbytes, flow.bytes) == (60 + 52 * 2, 1500 * 2, 164 + 3000)
    assert flow.dur == pytest.approx(0.6)
    assert (flow.min_len, flow.max_len) == (52, 1500)
    assert flow.mean_len == pytest.approx(flow.bytes / 5)
    assert flow.tcp_flags == "APS"
    assert flow.end_reason == "end_of_input"
    assert "192.0.2" not in str(flow.as_dict())  # no addresses in output


def test_initiator_defines_direction_even_if_server_port_is_lower():
    [flow], _ = run([pm(0, B, A, 80, 40000), pm(1, A, B, 40000, 80)])
    assert (flow.sport, flow.dport) == (80, 40000)  # first sender is the source


def test_separate_flows_by_five_tuple_and_protocol():
    packets = [pm(0, A, B, 1, 2), pm(0, A, B, 1, 2, proto=17), pm(0, A, C, 1, 2), pm(0, A, B, 1, 3)]
    flows, _ = run(packets)
    assert len(flows) == 4


def test_idle_timeout_splits_flows():
    flows, _ = run([pm(0, A, B, 1, 2), pm(5, A, B, 1, 2), pm(100, A, B, 1, 2)], idle_timeout=10)
    assert [f.pkts for f in flows] == [2, 1]
    assert flows[0].end_reason == "idle_timeout"


def test_active_timeout_splits_long_flows():
    packets = [pm(t, A, B, 1, 2) for t in range(0, 25, 5)]
    flows, _ = run(packets, idle_timeout=100, active_timeout=12)
    assert flows[0].end_reason == "active_timeout" and flows[0].pkts == 3
    assert sum(f.pkts for f in flows) == 5


def test_capacity_eviction_is_counted_not_silent():
    packets = [pm(i, A, B, 1000 + i, 80) for i in range(5)]
    flows, agg = run(packets, max_active=2, idle_timeout=1000)
    assert len(flows) == 5 and agg.evicted_for_capacity == 3
    assert sum(f.end_reason == "capacity" for f in flows) == 3


def test_invalid_aggregator_settings():
    with pytest.raises(ValueError):
        FlowAggregator(idle_timeout=0)
    with pytest.raises(ValueError):
        FlowAggregator(max_active=0)


# ----------------------------------------------------------------------------- feature mapping


def test_rules_cover_exactly_the_model_inputs(bundle):
    assert list(RULES) == list(bundle.schema.feature_order)
    not_computed = {n for n, r in RULES.items() if r.status == "not_computed"}
    assert not_computed == set(bundle.schema.constant_features)


def test_candidate_never_fabricates_values():
    [flow], _ = run(tcp_conversation())
    values = model_candidate(flow)
    for name, rule in RULES.items():
        if rule.status in ("incompatible", "not_computed"):
            assert values[name] is None, name
    assert values["proto"] == "HTTP" and values["proto_number"] == 6.0
    assert values["mean"] == pytest.approx(values["bytes"] / values["pkts"])
    assert values["rate"] == pytest.approx(values["bytes"] / values["dur"])
    assert values["sum"] == values["bytes"]


def test_zero_duration_flow_has_no_rate():
    [flow], _ = run([pm(5, A, B, 1, 53, proto=17)])
    assert flow.dur == 0 and model_candidate(flow)["rate"] is None


@pytest.mark.parametrize(
    "proto, dport, expected",
    [(6, 80, "HTTP"), (17, 53, "DNS"), (6, 53, None), (6, 445, None), (6, 8080, None),
     (1, 0, "ICMP"), (17, 5683, "CoAP")],
)  # fmt: skip
def test_application_label_only_when_unambiguous(proto, dport, expected):
    [flow], _ = run([pm(0, A, B, 40000, dport, proto=proto)])
    assert app_proto(flow) == expected


# ----------------------------------------------------------------------------- report and gate


def test_report_is_incompatible_and_gate_closed(bundle, service):
    flows, _ = run(tcp_conversation() + tcp_conversation(t0=500))
    ref = compatibility.load_training_reference()
    report = build_report(flows, bundle.schema.feature_order, ref, service, True)
    assert report["compatible"] is False
    assert report["flows_analyzed"] == 2
    assert set(report["blocking_features"]) >= {"spkts", "dpkts", "min", "max", "stddev", "flgs"}
    assert report["status_counts"] == {
        "incompatible": 10, "not_computed": 15, "approximated": 1, "derived": 9,
    }  # fmt: skip
    assert report["schema_validation"]["checked"] and not report["schema_validation"]["passed"]
    assert "spkts" in report["schema_validation"]["errors_by_feature"]
    # Even with live inference enabled in configuration, incompatible flows are not scored.
    assert report["inference_gate"]["allowed"] is False
    inv = {i["invariant"]: i for i in report["invariants"]}
    assert inv["spkts_equals_dpkts"]["training_share"] == 1.0
    assert inv["spkts_equals_dpkts"]["extracted_share"] == 0.0


def test_report_with_no_flows(bundle):
    report = build_report([], bundle.schema.feature_order, None, None, False)
    assert report["compatible"] is False and report["flows_analyzed"] == 0


@pytest.mark.parametrize(
    "compatible, enabled, allowed",
    [(False, False, False), (False, True, False), (True, False, False), (True, True, True)],
)
def test_gate_requires_compatibility_and_explicit_enablement(compatible, enabled, allowed):
    gate = evaluate_gate(compatible, enabled)
    assert gate.allowed is allowed
    assert (len(gate.reasons) == 0) is allowed
