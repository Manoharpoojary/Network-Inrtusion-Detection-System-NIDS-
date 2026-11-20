"""Live-adapted model: loading, v5-compatible flows, scoring, capture integration and API.

Expected feature values below are hand-computed from flow_aggregator_v5.py / to_model_features in
the model's source project (0.1 s windows, len(ip) lengths, population std, microseconds).
Packets are SYNTHETIC metadata (documentation addresses); no network or capture device is used.
"""

import math

import pytest

from major_project.core.config import DEFAULT_LIVE_MODEL_PATH, DEFAULT_LIVE_MODEL_SHA256
from major_project.services.capture_service import CaptureError, CaptureLimits, LiveCaptureManager
from major_project.services.flow_features import PacketMeta
from major_project.services.live_detection import (
    LIVE_FEATURES,
    LiveDetector,
    LiveFlowAggregator,
    extract_live_flows,
    load_live_model,
)
from major_project.services.model_loader import ArtifactIntegrityError, ModelLoadError
from tests.api_helpers import api_client
from tests.test_capture_service import FakeSniffer, wait_for

A, B, C = "192.0.2.10", "198.51.100.20", "192.0.2.30"
TEST_CSV = DEFAULT_LIVE_MODEL_PATH.parent / "binary_test.csv"

needs_model = pytest.mark.skipif(not DEFAULT_LIVE_MODEL_PATH.is_file(), reason="live model absent")


def pm(ts, src, dst, sport, dport, ip_len, flags="", proto=6):
    return PacketMeta(ts, src, dst, sport, dport, proto, ip_len + 14, flags, ip_len)


def tcp_flow():
    """5 packets in one 0.1 s window. IP lengths 60, 1040, 140, 540, 52; client-only FIN."""
    return [
        pm(10.000, A, B, 40000, 80, 60, "S"),
        pm(10.010, B, A, 80, 40000, 1040, "SA"),
        pm(10.030, A, B, 40000, 80, 140, "PA"),
        pm(10.060, B, A, 80, 40000, 540, "PA"),
        pm(10.080, A, B, 40000, 80, 52, "FA"),
    ]


def pstdev(values):
    m = sum(values) / len(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / len(values))


@pytest.fixture(scope="module")
def live():
    if not DEFAULT_LIVE_MODEL_PATH.is_file():
        pytest.skip("live model absent")
    return load_live_model(DEFAULT_LIVE_MODEL_PATH, DEFAULT_LIVE_MODEL_SHA256)


# ----------------------------------------------------------------------------- v5-compatible flows


def test_feature_definitions_match_v5():
    [flow] = extract_live_flows(tcp_flow())
    f = flow.features()
    assert list(f) == list(LIVE_FEATURES)
    assert (f["Protocol"], f["Src_Port"], f["Dst_Port"]) == (6.0, 40000.0, 80.0)
    assert f["Flow_Duration"] == pytest.approx(80_000)  # microseconds
    assert (f["Tot_Fwd_Pkts"], f["Tot_Bwd_Pkts"]) == (3.0, 2.0)
    assert (f["TotLen_Fwd_Pkts"], f["TotLen_Bwd_Pkts"]) == (252.0, 1580.0)  # IP lengths
    lengths = [60, 1040, 140, 540, 52]
    assert (f["Pkt_Len_Min"], f["Pkt_Len_Max"]) == (52.0, 1040.0)
    assert f["Pkt_Len_Mean"] == pytest.approx(sum(lengths) / 5)
    assert f["Pkt_Len_Std"] == pytest.approx(pstdev(lengths))  # population std, as v5
    iats = [10_000, 20_000, 30_000, 20_000]
    assert f["Flow_IAT_Mean"] == pytest.approx(20_000)
    assert f["Flow_IAT_Std"] == pytest.approx(pstdev(iats))
    assert {k: f[k] for k in LIVE_FEATURES[-5:]} == {
        "SYN_Flag_Cnt": 1.0, "ACK_Flag_Cnt": 1.0, "RST_Flag_Cnt": 0.0,
        "FIN_Flag_Cnt": 1.0, "PSH_Flag_Cnt": 1.0,
    }  # fmt: skip


def test_flows_are_cut_into_0_1_second_windows():
    # Same 5-tuple every 30 ms for 240 ms: v5 starts a new flow once ts - start >= 0.1.
    pkts = [pm(round(i * 0.03, 3), A, B, 40000, 443, 100, "A") for i in range(9)]
    flows = extract_live_flows(pkts)
    assert [len(f.lengths) for f in flows] == [4, 4, 1]
    assert all(f.features()["Flow_Duration"] < 100_000 for f in flows)


def test_idle_flows_finish_after_0_1_seconds():
    flows = extract_live_flows(
        [pm(0.0, A, B, 1, 53, 60, proto=17), pm(0.15, A, B, 1, 53, 60, proto=17)]
    )
    assert [len(f.lengths) for f in flows] == [1, 1]


def test_rst_closes_flow_including_that_packet():
    agg = LiveFlowAggregator()
    assert agg.add(pm(0.0, A, B, 50000, 80, 60, "S")) == []
    [closed] = agg.add(pm(0.01, B, A, 80, 50000, 40, "RA"))
    assert len(closed.lengths) == 2 and closed.features()["RST_Flag_Cnt"] == 1.0
    assert agg.active_flows == 0


def test_fin_closes_only_after_both_directions():
    agg = LiveFlowAggregator()
    agg.add(pm(0.0, A, B, 40000, 80, 60, "S"))
    assert agg.add(pm(0.01, A, B, 40000, 80, 52, "FA")) == []  # one direction: still open
    [closed] = agg.add(pm(0.02, B, A, 80, 40000, 52, "FA"))
    assert len(closed.lengths) == 3


def test_direction_and_ports_come_from_first_packet():
    [flow] = extract_live_flows([pm(0.0, B, A, 443, 51000, 1500), pm(0.01, A, B, 51000, 443, 52)])
    f = flow.features()
    assert (f["Src_Port"], f["Dst_Port"], f["Tot_Fwd_Pkts"], f["TotLen_Fwd_Pkts"]) == (
        443.0, 51000.0, 1.0, 1500.0,
    )  # fmt: skip


def test_only_ipv4_tcp_udp_are_used():
    agg = LiveFlowAggregator()
    agg.add(pm(0.0, A, B, 0, 0, 84, proto=1))  # ICMP
    agg.add(pm(0.0, "2001:db8::1", "2001:db8::2", 1, 443, 80))  # IPv6
    assert agg.active_flows == 0 and agg.skipped_packets == 2


def test_flow_table_is_bounded():
    agg = LiveFlowAggregator(max_active=2)
    done = []
    for i in range(4):
        done += agg.add(pm(0.0, A, C, 1000 + i, 80, 60, "S"))
    assert agg.active_flows == 2 and agg.evicted_for_capacity == 2 and len(done) == 2


def test_ip_length_from_real_packet():
    scapy = pytest.importorskip("scapy.all")
    from major_project.services.flow_features import packet_meta

    p = (
        scapy.Ether()
        / scapy.IP(src=A, dst=B)
        / scapy.TCP(sport=1, dport=80)
        / scapy.Raw(b"x" * 123)
    )
    built = scapy.Ether(bytes(p))
    built.time = 1.0
    assert packet_meta(built).ip_len == 20 + 20 + 123  # len(ip), as in v5


# ----------------------------------------------------------------------------- model


@needs_model
def test_live_model_loads_with_expected_schema(live):
    assert tuple(live.model.feature_names_in_) == LIVE_FEATURES
    assert sorted(map(str, live.model.classes_)) == ["Anomaly", "Normal"]
    assert len(live.model.estimators_) == 200
    assert live.version == "rf-live-" + DEFAULT_LIVE_MODEL_SHA256[:12]


@needs_model
@pytest.mark.skipif(not TEST_CSV.is_file(), reason="binary_test.csv absent")
def test_reproduces_reported_test_accuracy(live):
    """live_adaptation_report.txt: held-out test accuracy 0.998777 on binary_test.csv."""
    import pandas as pd
    from sklearn.metrics import accuracy_score

    d = pd.read_csv(TEST_CSV)
    X = d[list(LIVE_FEATURES)].copy()
    for c in LIVE_FEATURES[-5:]:
        X[c] = (X[c] > 0).astype(int)
    assert round(accuracy_score(d["Label"], live.model.predict(X)), 6) == 0.998777


def test_live_model_hash_and_missing_file(tmp_path):
    if DEFAULT_LIVE_MODEL_PATH.is_file():
        with pytest.raises(ArtifactIntegrityError):
            load_live_model(DEFAULT_LIVE_MODEL_PATH, "0" * 64)
    with pytest.raises(ModelLoadError, match="not found"):
        load_live_model(tmp_path / "missing.joblib", None)


@needs_model
def test_detector_scores_flows(live):
    det = LiveDetector(live, threshold=0.5)
    [d] = det.score(extract_live_flows(tcp_flow()))
    assert d.label in ("Anomaly", "Normal")
    assert 0.0 <= d.anomaly_probability <= 1.0
    assert d.label == ("Anomaly" if d.anomaly_probability >= 0.5 else "Normal")
    assert (d.protocol, d.dport, d.fwd_pkts, d.bwd_pkts) == ("TCP", 80, 3, 2)
    assert "192.0.2" not in str(d.as_dict())
    assert det.score([]) == []
    assert (
        LiveDetector(live, threshold=0.0).score(extract_live_flows(tcp_flow()))[0].label
        == "Anomaly"
    )


def test_detector_rejects_bad_threshold(live):
    with pytest.raises(ValueError):
        LiveDetector(live, threshold=1.5)


# ----------------------------------------------------------------------------- capture integration


@needs_model
def test_detection_session_scores_and_persists(live):
    persisted = []
    mgr = LiveCaptureManager(
        CaptureLimits(startup_grace_seconds=0.02),
        feature_order=[],
        detector=LiveDetector(live),
        sniffer_factory=lambda iface, bpf, prn: FakeSniffer(prn, packets=tcp_flow()),
        interface_resolver=lambda name: name,
        meta_fn=lambda p: p,
        on_detections=lambda s, found: persisted.extend(found),
    )
    st = mgr.start("Wi-Fi", detect=True)
    assert st["detection"]["enabled"] and st["session"]["detect"]
    assert wait_for(lambda: mgr.status()["session"]["counters"]["packets_queued"] == 5)
    final = mgr.stop()
    c = final["session"]["counters"]
    assert c["flows_scored"] == 1 and c["anomalies"] + c["normal"] == 1
    [recent] = final["detection"]["recent"]
    assert recent["dport"] == 80 and recent["label"] in ("Anomaly", "Normal")
    assert len(persisted) == 1


def test_detect_without_model_is_refused():
    mgr = LiveCaptureManager(CaptureLimits(), feature_order=[], interface_resolver=lambda n: n)
    with pytest.raises(CaptureError) as exc:
        mgr.start("Wi-Fi", detect=True)
    assert exc.value.code == "live_model_unavailable" and mgr.state == "stopped"


@needs_model
def test_scoring_failure_does_not_stop_capture(live):
    class Broken(LiveDetector):
        def score(self, flows):
            raise RuntimeError("boom")

    mgr = LiveCaptureManager(
        CaptureLimits(startup_grace_seconds=0.02),
        feature_order=[],
        detector=Broken(live),
        sniffer_factory=lambda iface, bpf, prn: FakeSniffer(prn, packets=tcp_flow()),
        interface_resolver=lambda name: name,
        meta_fn=lambda p: p,
    )
    mgr.start("Wi-Fi", detect=True)
    final = mgr.stop()
    assert final["state"] == "stopped" and final["session"]["counters"]["scoring_errors"] == 1


# ----------------------------------------------------------------------------- API


@needs_model
def test_live_detection_api_end_to_end(tmp_path):
    with api_client(tmp_path, client_host="127.0.0.1") as c:
        info = c.get("/api/network/live/model").json()
        assert info["available"] and info["features"] == list(LIVE_FEATURES)
        assert info["time_unit"] == "microseconds" and info["pickled_sklearn_version"] == "1.9.1"
        assert info["flow_window_seconds"] == 0.1

        cap = c.app.state.nids.capture
        cap.interface_resolver = lambda name: name
        cap.sniffer_factory = lambda iface, bpf, prn: FakeSniffer(prn, packets=tcp_flow())
        cap.meta_fn = lambda p: p
        cap.limits.startup_grace_seconds = 0.02
        body = {"interface": "Wi-Fi", "authorized": True, "detect": True}
        assert c.post("/api/network/live/start", json=body).json()["detection"]["enabled"]
        stopped = c.post("/api/network/live/stop").json()
        assert stopped["session"]["counters"]["flows_scored"] == 1

        listing = c.get("/api/network/live/detections").json()
        assert listing["total"] == 1 and listing["items"][0]["source"] == "live"
        assert len(listing["items"][0]["features"]) == 19
        assert listing["totals"]["anomaly"] + listing["totals"]["normal"] == 1
        label = listing["items"][0]["label"]
        assert c.get("/api/network/live/detections", params={"label": label}).json()["total"] == 1
        assert b"192.0.2.10" not in (tmp_path / "test.db").read_bytes()
        # The original dataset model was not used: no predictions or alerts were created.
        assert c.get("/api/dashboard/summary").json()["total_processed"] == 0


def test_live_model_unavailable_api(tmp_path):
    with api_client(tmp_path, client_host="127.0.0.1", live_model_sha256="0" * 64) as c:
        info = c.get("/api/network/live/model").json()
        assert info["available"] is False and "SHA-256" in info["error"]
        r = c.post(
            "/api/network/live/start",
            json={"interface": "Wi-Fi", "authorized": True, "detect": True},
        )
        assert r.status_code == 503 and r.json()["error"]["code"] == "live_model_unavailable"
        assert c.get("/api/health").json()["status"] == "ok"  # original model unaffected


@needs_model
def test_pcap_upload_is_scored_by_live_model(tmp_path):
    scapy = pytest.importorskip("scapy.all")
    pkts = [
        scapy.Ether() / scapy.IP(src=A, dst=B) / scapy.TCP(sport=40000, dport=80, flags="S"),
        scapy.Ether() / scapy.IP(src=B, dst=A) / scapy.TCP(sport=80, dport=40000, flags="SA"),
        scapy.Ether()
        / scapy.IP(src=A, dst=B)
        / scapy.UDP(sport=5353, dport=53)
        / scapy.Raw(b"q" * 30),
    ]
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000 + i * 0.01
    path = tmp_path / "t.pcap"
    scapy.wrpcap(str(path), pkts)
    with api_client(tmp_path) as c:
        run = c.post(
            "/api/network/pcap",
            files={"file": ("t.pcap", path.read_bytes(), "application/octet-stream")},
        ).json()
        ld = run["report"]["live_detection"]
        assert ld["available"] and ld["flows_scored"] == 2
        assert ld["anomalies"] + ld["normal"] == 2
        stored = c.get("/api/network/live/detections", params={"source": "pcap"}).json()
        assert stored["total"] == 2 and stored["items"][0]["run_id"] == run["id"]
        assert run["report"]["predictions"] is None  # original model still not used
