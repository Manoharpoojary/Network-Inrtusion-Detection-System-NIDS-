"""Live-adapted model: loading, the 19 packet features, scoring, capture integration and API.

Packets are SYNTHETIC metadata (documentation addresses); no network or capture device is used.
"""

import math

import pytest

from major_project.core.config import DEFAULT_LIVE_MODEL_PATH, DEFAULT_LIVE_MODEL_SHA256
from major_project.services.capture_service import CaptureError, CaptureLimits, LiveCaptureManager
from major_project.services.flow_features import FlowAggregator, PacketMeta
from major_project.services.live_detection import (
    LIVE_FEATURES,
    LiveDetector,
    live_features,
    load_live_model,
)
from major_project.services.model_loader import ArtifactIntegrityError, ModelLoadError
from tests.api_helpers import api_client
from tests.test_capture_service import FakeSniffer, wait_for

A, B = "192.0.2.10", "198.51.100.20"

needs_model = pytest.mark.skipif(not DEFAULT_LIVE_MODEL_PATH.is_file(), reason="live model absent")


def pm(ts, src, dst, sport, dport, payload, flags="", proto=6, length=None):
    return PacketMeta(ts, src, dst, sport, dport, proto, length or payload + 54, flags, payload)


def tcp_flow():
    """Client sends 3 packets (payload 0, 100, 0), server 2 (payload 1000, 500)."""
    return [
        pm(10.000, A, B, 40000, 80, 0, "S"),
        pm(10.010, B, A, 80, 40000, 1000, "SA"),
        pm(10.030, A, B, 40000, 80, 100, "PA"),
        pm(10.060, B, A, 80, 40000, 500, "PA"),
        pm(10.100, A, B, 40000, 80, 0, "FA"),
    ]


def one_flow(packets, **kw):
    agg = FlowAggregator(**kw)
    for p in packets:
        agg.add(p)
    [flow] = agg.flush()
    return flow


@pytest.fixture(scope="module")
def live():
    if not DEFAULT_LIVE_MODEL_PATH.is_file():
        pytest.skip("live model absent")
    return load_live_model(DEFAULT_LIVE_MODEL_PATH, DEFAULT_LIVE_MODEL_SHA256)


# ----------------------------------------------------------------------------- features


def test_feature_definitions():
    f = live_features(one_flow(tcp_flow()), "microseconds")
    assert list(f) == list(LIVE_FEATURES)
    assert (f["Protocol"], f["Src_Port"], f["Dst_Port"]) == (6.0, 40000.0, 80.0)
    assert f["Flow_Duration"] == pytest.approx(100_000)  # 0.1 s in microseconds
    assert (f["Tot_Fwd_Pkts"], f["Tot_Bwd_Pkts"]) == (3.0, 2.0)
    assert (f["TotLen_Fwd_Pkts"], f["TotLen_Bwd_Pkts"]) == (100.0, 1500.0)  # payload bytes
    assert (f["Pkt_Len_Min"], f["Pkt_Len_Max"]) == (0.0, 1000.0)
    assert f["Pkt_Len_Mean"] == pytest.approx(1600 / 5)
    payloads = [0, 1000, 100, 500, 0]
    mean = sum(payloads) / 5
    sample_std = math.sqrt(sum((x - mean) ** 2 for x in payloads) / 4)
    assert f["Pkt_Len_Std"] == pytest.approx(sample_std)
    iats = [10_000, 20_000, 30_000, 40_000]  # microseconds
    assert f["Flow_IAT_Mean"] == pytest.approx(25_000)
    iat_mean = sum(iats) / 4
    assert f["Flow_IAT_Std"] == pytest.approx(math.sqrt(sum((x - iat_mean) ** 2 for x in iats) / 3))
    assert {k: f[k] for k in LIVE_FEATURES[-5:]} == {
        "SYN_Flag_Cnt": 1.0, "ACK_Flag_Cnt": 1.0, "RST_Flag_Cnt": 0.0,
        "FIN_Flag_Cnt": 1.0, "PSH_Flag_Cnt": 1.0,
    }  # fmt: skip


@pytest.mark.parametrize(
    "unit, scale", [("microseconds", 1e6), ("milliseconds", 1e3), ("seconds", 1)]
)
def test_time_unit(unit, scale):
    f = live_features(one_flow(tcp_flow()), unit)
    assert f["Flow_Duration"] == pytest.approx(0.1 * scale)
    assert f["Flow_IAT_Mean"] == pytest.approx(0.025 * scale)


def test_single_packet_flow_has_zero_time_stats():
    f = live_features(one_flow([pm(5.0, A, B, 5353, 53, 40, proto=17)]))
    assert (f["Flow_Duration"], f["Flow_IAT_Mean"], f["Flow_IAT_Std"], f["Pkt_Len_Std"]) == (
        0,
        0,
        0,
        0,
    )
    assert (f["Protocol"], f["Tot_Bwd_Pkts"]) == (17.0, 0.0)


def test_payload_length_from_real_headers():
    scapy = pytest.importorskip("scapy.all")
    from major_project.services.flow_features import packet_meta

    tcp = (
        scapy.Ether()
        / scapy.IP(src=A, dst=B)
        / scapy.TCP(sport=1, dport=80)
        / scapy.Raw(b"x" * 123)
    )
    udp = (
        scapy.Ether() / scapy.IP(src=A, dst=B) / scapy.UDP(sport=1, dport=53) / scapy.Raw(b"y" * 45)
    )
    ack = scapy.Ether() / scapy.IP(src=A, dst=B) / scapy.TCP(sport=1, dport=80, flags="A")
    for p, expected in [(tcp, 123), (udp, 45), (ack, 0)]:
        built = scapy.Ether(bytes(p))
        built.time = 1.0
        assert packet_meta(built).payload_len == expected


# ----------------------------------------------------------------------------- model


@needs_model
def test_live_model_loads_with_expected_schema(live):
    assert tuple(live.model.feature_names_in_) == LIVE_FEATURES
    assert sorted(map(str, live.model.classes_)) == ["Anomaly", "Normal"]
    assert len(live.model.estimators_) == 200
    assert live.version == "rf-live-" + DEFAULT_LIVE_MODEL_SHA256[:12]


def test_live_model_hash_and_missing_file(tmp_path):
    if DEFAULT_LIVE_MODEL_PATH.is_file():
        with pytest.raises(ArtifactIntegrityError):
            load_live_model(DEFAULT_LIVE_MODEL_PATH, "0" * 64)
    with pytest.raises(ModelLoadError, match="not found"):
        load_live_model(tmp_path / "missing.joblib", None)


@needs_model
def test_detector_scores_flows(live):
    det = LiveDetector(live, threshold=0.5)
    [d] = det.score([one_flow(tcp_flow())])
    assert d.label in ("Anomaly", "Normal")
    assert 0.0 <= d.anomaly_probability <= 1.0
    assert d.label == ("Anomaly" if d.anomaly_probability >= 0.5 else "Normal")
    assert (d.protocol, d.dport, d.fwd_pkts, d.bwd_pkts) == ("TCP", 80, 3, 2)
    assert "192.0.2" not in str(d.as_dict())
    assert det.score([]) == []
    assert LiveDetector(live, threshold=0.0).score([one_flow(tcp_flow())])[0].label == "Anomaly"


def test_detector_rejects_bad_settings(live):
    with pytest.raises(ValueError):
        LiveDetector(live, time_unit="hours")
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
