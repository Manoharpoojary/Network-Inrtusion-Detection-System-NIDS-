"""Live-capture endpoints and API security controls (fake sniffer; no network or admin rights)."""

import time

import pytest

from tests.api_helpers import api_client, csv_bytes, synthetic_record, upload
from tests.test_capture_service import FakeSniffer, meta, wait_for

START = {"interface": "Wi-Fi", "authorized": True, "max_duration_seconds": 30}


def _fake_capture(client, packets=()):
    cap = client.app.state.nids.capture
    cap.interface_resolver = lambda name: {"name": name}
    cap.sniffer_factory = lambda iface, bpf, prn: FakeSniffer(prn, packets=packets)
    cap.meta_fn = lambda p: p
    cap.limits.startup_grace_seconds = 0.02
    return cap


@pytest.fixture
def local(tmp_path):
    with api_client(tmp_path, client_host="127.0.0.1") as c:
        yield c


# ----------------------------------------------------------------------------- capture control


@pytest.mark.parametrize(
    "method, path",
    [
        ("get", "/api/network/live/status"),
        ("post", "/api/network/live/start"),
        ("post", "/api/network/live/stop"),
        ("post", "/api/network/live/reset"),
        ("post", "/api/network/capture-check"),
    ],
)
def test_capture_endpoints_reject_remote_clients(tmp_path, method, path):
    with api_client(tmp_path, client_host="203.0.113.7") as c:
        kwargs = {"json": START} if path.endswith("start") else {}
        r = getattr(c, method)(path, **kwargs)
    assert r.status_code == 403 and r.json()["error"]["code"] == "local_only"


def test_live_session_via_api_is_persisted_without_addresses(local, tmp_path):
    _fake_capture(local, packets=[meta(), meta(src="198.51.100.20", dst="192.0.2.10",
                                               sport=80, dport=40000)])  # fmt: skip
    assert local.get("/api/network/live/status").json()["state"] == "stopped"
    r = local.post("/api/network/live/start", json=START)
    assert r.status_code == 200 and r.json()["state"] == "running"
    assert wait_for(
        lambda: (
            local.get("/api/network/live/status").json()["session"]["counters"]["packets_queued"]
            == 2
        )
    )
    busy = local.post("/api/network/live/start", json=START)
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "capture_busy"

    stopped = local.post("/api/network/live/stop").json()
    assert stopped["state"] == "stopped" and stopped["predictions"] is None
    assert stopped["live_inference"]["gate_allowed"] is False
    assert local.post("/api/network/live/stop").status_code == 409

    runs = local.get("/api/network/runs").json()["items"]
    assert [r["kind"] for r in runs] == ["live"]
    detail = local.get(f"/api/network/runs/{runs[0]['id']}").text
    assert "192.0.2.10" not in detail and "198.51.100.20" not in detail
    assert b"192.0.2.10" not in (tmp_path / "test.db").read_bytes()
    # Nothing was scored or turned into alerts.
    assert local.get("/api/dashboard/summary").json()["total_processed"] == 0


def test_live_capture_failure_returns_classified_error(local):
    cap = _fake_capture(local)
    cap.sniffer_factory = lambda iface, bpf, prn: FakeSniffer(
        prn, fail_in_thread=PermissionError(1, "Operation not permitted")
    )
    r = local.post("/api/network/live/start", json=START)
    assert r.status_code == 503 and r.json()["error"]["code"] == "permission_denied"
    assert local.get("/api/network/live/status").json()["state"] == "error"


def test_authorization_must_be_confirmed(local):
    _fake_capture(local)
    r = local.post("/api/network/live/start", json=dict(START, authorized=False))
    assert r.status_code == 422 and r.json()["error"]["code"] == "authorization_not_confirmed"
    r = local.post("/api/network/live/start", json={"interface": "Wi-Fi"})
    assert r.status_code == 422


@pytest.mark.parametrize(
    "body",
    [
        dict(START, bpf_filter="port 53; rm -rf /"),
        dict(START, bpf_filter="$(id)"),
        dict(START, max_duration_seconds=99999),
        dict(START, interface=""),
        dict(START, unexpected="x"),
    ],
)
def test_invalid_start_requests_rejected(local, body):
    _fake_capture(local)
    assert local.post("/api/network/live/start", json=body).status_code == 422
    assert local.get("/api/network/live/status").json()["state"] == "stopped"


def test_capture_token_required_when_configured(tmp_path):
    with api_client(tmp_path, client_host="127.0.0.1", capture_token="s3cret-token") as c:
        _fake_capture(c)
        r = c.post("/api/network/live/start", json=START)
        assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_capture_token"
        r = c.post("/api/network/live/start", json=START, headers={"X-Capture-Token": "wrong"})
        assert r.status_code == 401
        r = c.post(
            "/api/network/live/start", json=START, headers={"X-Capture-Token": "s3cret-token"}
        )
        assert r.status_code == 200
        assert c.post("/api/network/live/stop").status_code == 401
        ok = c.post("/api/network/live/stop", headers={"X-Capture-Token": "s3cret-token"})
        assert ok.status_code == 200
        assert "s3cret-token" not in ok.text


def test_app_shutdown_stops_running_capture(tmp_path):
    with api_client(tmp_path, client_host="127.0.0.1") as c:
        cap = _fake_capture(c, packets=[meta()])
        c.post("/api/network/live/start", json=START)
        assert cap.state == "running"
    assert cap.state == "stopped"
    assert cap.status()["session"]["stop_reason"] == "application_shutdown"


# ----------------------------------------------------------------------------- origin and size


def test_cross_site_post_is_rejected(tmp_path):
    with api_client(tmp_path) as c:
        r = c.post(
            "/api/predict", json=synthetic_record(), headers={"Origin": "http://evil.example"}
        )
        assert r.status_code == 403 and r.json()["error"]["code"] == "origin_not_allowed"
        r = c.post(
            "/api/predict", json=synthetic_record(), headers={"Origin": "http://localhost:5173"}
        )
        assert r.status_code == 200
        # GET requests and non-browser clients (no Origin header) are unaffected.
        assert c.get("/api/health", headers={"Origin": "http://evil.example"}).status_code == 200
        assert c.post("/api/predict", json=synthetic_record()).status_code == 200


def test_oversized_upload_rejected_before_parsing(tmp_path):
    with api_client(tmp_path, max_upload_bytes=2048) as c:
        data = csv_bytes([synthetic_record()] * 700)
        assert len(data) > 2048 + 64 * 1024
        r = upload(c, data)
    assert r.status_code == 413 and r.json()["error"]["code"] == "upload_too_large"


def test_invalid_content_length_rejected(tmp_path):
    with api_client(tmp_path) as c:
        r = c.post(
            "/api/analyze/csv",
            content=b"x",
            headers={"Content-Length": "abc", "Content-Type": "text/csv"},
        )
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_content_length"


def test_status_poll_is_fast(local):
    _fake_capture(local)
    start = time.perf_counter()
    for _ in range(20):
        local.get("/api/network/live/status")
    assert time.perf_counter() - start < 5


def test_reset_via_api_keeps_history(local):
    _fake_capture(local, packets=[meta()])
    local.post("/api/network/live/start", json=START)
    busy = local.post("/api/network/live/reset")
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "capture_busy"
    local.post("/api/network/live/stop")
    r = local.post("/api/network/live/reset")
    assert r.status_code == 200 and r.json()["state"] == "stopped" and r.json()["session"] is None
    assert local.get("/api/network/live/status").json()["session"] is None
    assert local.get("/api/network/runs").json()["total"] == 1


def test_reset_requires_token_when_configured(tmp_path):
    with api_client(tmp_path, client_host="127.0.0.1", capture_token="tok") as c:
        assert c.post("/api/network/live/reset").status_code == 401
        assert (
            c.post("/api/network/live/reset", headers={"X-Capture-Token": "tok"}).status_code == 200
        )
