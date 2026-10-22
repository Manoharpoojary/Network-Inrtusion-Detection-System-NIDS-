"""Network endpoints with SYNTHETIC captures written by Scapy into tmp_path.

No real network, capture device or administrator rights are used. Addresses are from the reserved
documentation ranges (192.0.2.0/24, 198.51.100.0/24) and must never appear in responses or the DB.
"""

import struct

import pytest

from tests.api_helpers import api_client

scapy_all = pytest.importorskip("scapy.all", reason="capture extra not installed")
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap  # noqa: E402
from scapy.utils import PcapNgWriter  # noqa: E402

A, B = "192.0.2.10", "198.51.100.20"


def _packets():
    pkts = [
        Ether() / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="S"),
        Ether() / IP(src=B, dst=A) / TCP(sport=80, dport=40000, flags="SA"),
        Ether() / IP(src=A, dst=B) / TCP(sport=40000, dport=80, flags="PA") / Raw(b"G" * 200),
        Ether() / IP(src=B, dst=A) / TCP(sport=80, dport=40000, flags="PA") / Raw(b"H" * 900),
        Ether() / IP(src=A, dst=B) / UDP(sport=5353, dport=53) / Raw(b"q" * 30),
        Ether() / IP(src=A, dst=B) / ICMP(),
        Ether() / ARP(psrc=A, pdst=B),  # non-IP
        Ether() / IP(src=A, dst=B, proto=6) / Raw(b"\x00\x01"),  # TCP header missing: malformed
    ]
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000.0 + i * 0.25
    return pkts


@pytest.fixture
def pcap_bytes(tmp_path):
    path = tmp_path / "synthetic.pcap"
    wrpcap(str(path), _packets())
    return path.read_bytes()


@pytest.fixture
def client(tmp_path):
    with api_client(tmp_path) as c:
        yield c


def _upload(client, data, name="capture.pcap"):
    return client.post(
        "/api/network/pcap", files={"file": (name, data, "application/vnd.tcpdump.pcap")}
    )


# ----------------------------------------------------------------------------- PCAP analysis


def test_pcap_analysis_extracts_flows_and_reports_incompatibility(client, pcap_bytes, tmp_path):
    r = _upload(client, pcap_bytes)
    assert r.status_code == 200, r.text
    run = r.json()
    assert run["kind"] == "pcap" and run["status"] == "completed"
    assert run["packets_read"] == 8
    assert run["ip_packets"] == 6 and run["non_ip_packets"] == 1 and run["malformed_packets"] == 1
    assert run["flows_extracted"] == 3  # TCP conversation, DNS, ICMP
    report = run["report"]
    assert run["compatible"] is False and report["compatible"] is False
    assert report["inference_gate"]["allowed"] is False
    assert report["predictions"] is None and report["predictions_note"].startswith("Not scored")
    tcp = next(f for f in report["flow_sample"] if f["observed"]["dport"] == 80)
    assert tcp["observed"]["spkts"] == 2 and tcp["observed"]["dpkts"] == 2
    assert tcp["model_features"]["proto"] == "HTTP"
    assert tcp["model_features"]["spkts"] is None  # never fabricated

    # Persisted and retrievable; addresses appear nowhere.
    detail = client.get(f"/api/network/runs/{run['id']}")
    assert detail.status_code == 200 and detail.json()["report"]["flows_analyzed"] == 3
    assert client.get("/api/network/runs").json()["total"] == 1
    for text in (r.text, detail.text):
        assert A not in text and B not in text
    db_bytes = (tmp_path / "test.db").read_bytes()
    assert A.encode() not in db_bytes and B.encode() not in db_bytes


def test_extracted_flows_are_not_sent_to_the_model_even_if_enabled(tmp_path, pcap_bytes):
    with api_client(tmp_path, live_inference_enabled=True) as c:
        before = c.get("/api/dashboard/summary").json()["total_processed"]
        report = _upload(c, pcap_bytes).json()["report"]
        assert report["inference_gate"]["allowed"] is False
        assert "not compatible" in report["inference_gate"]["reasons"][0]
        assert c.get("/api/dashboard/summary").json()["total_processed"] == before == 0


def test_pcapng_is_supported(client, tmp_path):
    path = tmp_path / "synthetic.pcapng"
    writer = PcapNgWriter(str(path))
    for p in _packets()[:4]:
        writer.write(p)
    writer.close()
    run = _upload(client, path.read_bytes(), "capture.pcapng").json()
    assert run["packets_read"] == 4 and run["flows_extracted"] == 1


def test_truncated_capture_keeps_what_was_read(client, pcap_bytes):
    r = _upload(client, pcap_bytes[:-25])
    assert r.status_code == 200
    assert r.json()["status"] in ("completed", "partial")
    assert 1 <= r.json()["packets_read"] <= 8


def test_corrupt_record_header_stops_reading_with_partial_status(client, pcap_bytes):
    # Overwrite the 4th record's captured-length field with an impossible value.
    data = bytearray(pcap_bytes)
    offset, records = 24, 0
    while records < 3:
        incl_len = struct.unpack_from("<I", data, offset + 8)[0]
        offset += 16 + incl_len
        records += 1
    struct.pack_into("<I", data, offset + 8, 0x7FFFFFFF)
    r = _upload(client, bytes(data))
    assert r.status_code == 200
    run = r.json()
    # Scapy returns the corrupt record as a truncated packet (and warns) instead of raising.
    assert run["packets_read"] == 4
    assert run["status"] == "partial" and run["stats"]["truncated_records"] == 1


@pytest.mark.parametrize(
    "data, code",
    [(b"", "invalid_capture_file"), (b"hello,world\n1,2\n" * 4, "invalid_capture_file")],
)
def test_non_capture_files_rejected(client, data, code):
    r = _upload(client, data)
    assert r.status_code == 400 and r.json()["error"]["code"] == code


def test_pcap_size_limit(tmp_path, pcap_bytes):
    with api_client(tmp_path, max_pcap_bytes=1024) as c:
        r = _upload(c, pcap_bytes + b"\x00" * 2048)
    assert r.status_code == 413 and r.json()["error"]["code"] == "upload_too_large"


def test_packet_limit_is_reported(tmp_path, pcap_bytes):
    with api_client(tmp_path, max_pcap_packets=3) as c:
        run = _upload(c, pcap_bytes).json()
    assert run["packets_read"] == 3 and run["stats"]["packet_limit_reached"] is True


def test_flow_cap_counts_unanalysed_flows(tmp_path, pcap_bytes):
    with api_client(tmp_path, max_flows_analyzed=1) as c:
        run = _upload(c, pcap_bytes).json()
    assert run["stats"]["flows_extracted"] == 3 and run["stats"]["flows_not_analyzed"] == 2
    assert run["report"]["flows_analyzed"] == 1


def test_scapy_missing_returns_503(client, pcap_bytes, monkeypatch):
    from major_project.api.routes import network
    from major_project.services.pcap_analysis import CaptureLibraryUnavailableError

    def unavailable(*a, **k):
        raise CaptureLibraryUnavailableError("Scapy is not installed")

    monkeypatch.setattr(network, "analyze_capture", unavailable)
    r = _upload(client, pcap_bytes)
    assert r.status_code == 503 and r.json()["error"]["code"] == "capture_unavailable"


def test_unknown_run(client):
    assert client.get("/api/network/runs/nope").status_code == 404


# ----------------------------------------------------------------------------- mapping, interfaces
