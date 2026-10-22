"""Interface discovery, capture-check and feature-mapping endpoints.

These tests do not need Scapy, a capture device, network access or administrator rights:
psutil and Scapy are faked where their output matters.
"""

from types import SimpleNamespace

import pytest

from major_project.services import capture_diagnostics, interfaces
from tests.api_helpers import api_client


@pytest.fixture
def client(tmp_path):
    with api_client(tmp_path) as c:
        yield c


def test_feature_mapping_endpoint(client):
    m = client.get("/api/network/feature-mapping").json()
    assert len(m["features"]) == 35
    statuses = {f["feature"]: f["status"] for f in m["features"]}
    assert statuses["spkts"] == "incompatible" and statuses["pkts"] == "derived"
    assert m["training_invariants"]["spkts_equals_dpkts"]["share"] == 1.0


class FakePsutil:
    def __init__(self, fail_counters=False):
        self.fail_counters = fail_counters

    def net_if_stats(self):
        return {
            "Wi-Fi": SimpleNamespace(isup=True, speed=866, mtu=1500),
            "Ethernet": SimpleNamespace(isup=False, speed=0, mtu=1500),
        }

    def net_io_counters(self, pernic=False):
        if self.fail_counters:
            raise PermissionError("denied")
        return {
            "Wi-Fi": SimpleNamespace(
                bytes_sent=1, bytes_recv=2, packets_sent=3, packets_recv=4,
                errin=0, errout=0, dropin=5, dropout=0,
            )
        }  # fmt: skip


def _fake_scapy_loader():
    iface = SimpleNamespace(
        name="Wi-Fi", network_name="NPF_x", description="Fake WLAN", index=3,
        flags="UP+RUNNING+WIRELESS+OK", ip="192.0.2.99", mac="00:00:5e:00:53:01",
    )  # fmt: skip
    conf = SimpleNamespace(ifaces={"x": iface}, iface=iface, use_npcap=True, use_pcap=True)
    return conf, "2.8.0"


def test_interface_discovery_merges_psutil_and_scapy(monkeypatch):
    monkeypatch.setattr(
        capture_diagnostics,
        "driver_status",
        lambda conf, system: capture_diagnostics.DriverStatus("Npcap", True),
    )
    out = interfaces.discover_interfaces(FakePsutil(), scapy_loader=_fake_scapy_loader)
    by = {i["name"]: i for i in out["interfaces"]}
    assert by["Wi-Fi"]["visible_to_scapy"] and by["Wi-Fi"]["is_wireless"]
    assert by["Wi-Fi"]["speed_mbps"] == 866 and by["Wi-Fi"]["counters"]["drops_in"] == 5
    assert by["Ethernet"]["is_up"] is False and by["Ethernet"]["visible_to_scapy"] is False
    assert by["Ethernet"]["counters"] is None and by["Ethernet"]["speed_mbps"] is None
    text = str(out)
    assert "192.0.2.99" not in text and "00:00:5e" not in text


def test_interface_discovery_survives_counter_and_scapy_failures():
    def no_scapy():
        raise capture_diagnostics.ScapyUnavailableError("scapy_missing", "not installed")

    out = interfaces.discover_interfaces(FakePsutil(fail_counters=True), scapy_loader=no_scapy)
    assert {i["name"] for i in out["interfaces"]} == {"Wi-Fi", "Ethernet"}
    assert all(i["counters"] is None and not i["visible_to_scapy"] for i in out["interfaces"])
    assert any("counters unavailable" in n for n in out["notes"])
    assert out["scapy"]["available"] is False


def test_interfaces_endpoint_returns_real_interfaces_without_addresses(client):
    import psutil

    r = client.get("/api/network/interfaces")
    assert r.status_code == 200
    names = {i["name"] for i in r.json()["interfaces"]}
    assert set(psutil.net_if_stats()) <= names
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.address and len(a.address) > 6 and not a.address.startswith(("127.", "::1")):
                assert a.address not in r.text


def test_capture_check_is_local_only(client):
    r = client.post("/api/network/capture-check")
    assert r.status_code == 403 and r.json()["error"]["code"] == "local_only"


def test_capture_check_from_localhost_uses_diagnostic(tmp_path, monkeypatch):
    calls = []

    def fake_run(interface=None, check=True, **kw):
        calls.append((interface, check))
        return capture_diagnostics.DiagnosticReport(
            platform={"system": "Windows", "release": "11", "is_wsl": False, "is_admin": False},
            scapy=capture_diagnostics.ScapyStatus(True, "2.8.0"),
            driver=None,
            interfaces=[],
            capture_check=capture_diagnostics.CaptureCheck(
                "unavailable", "Wi-Fi", "permission_denied", "denied"
            ),
        )

    monkeypatch.setattr(capture_diagnostics, "run_diagnostics", fake_run)
    with api_client(tmp_path, client_host="127.0.0.1") as c:
        body = c.post("/api/network/capture-check", params={"interface": "Wi-Fi"}).json()
    assert calls == [("Wi-Fi", True)]
    assert body["capture_check"]["error_code"] == "permission_denied"
    assert body["live_inference"]["enabled"] is False
