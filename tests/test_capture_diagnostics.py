"""Capture diagnostic tests. Scapy, psutil and the capture socket are all faked: no network access,
no administrator rights and no real packet capture are needed."""

import errno
import json
from types import SimpleNamespace

import pytest

from major_project.services import capture_diagnostics as diag
from major_project.services.capture_diagnostics import (
    ScapyUnavailableError,
    classify_capture_error,
    run_diagnostics,
)

WINDOWS = {
    "system": "Windows",
    "release": "11",
    "python": "3.12",
    "is_wsl": False,
    "is_admin": False,
}
LINUX = {"system": "Linux", "release": "6.8", "python": "3.12", "is_wsl": False, "is_admin": False}
WSL = dict(LINUX, release="5.15.153.1-microsoft-standard-WSL2", is_wsl=True)


def _iface(name, flags="UP+RUNNING+OK", ip="192.0.2.10", desc="Fake adapter", index=1):
    return SimpleNamespace(
        name=name, network_name=f"\\Device\\NPF_{name}", description=desc, index=index,
        flags=flags, ip=ip, mac="00:11:22:33:44:55",
    )  # fmt: skip


def _conf(*ifaces, default=0, use_npcap=True, use_pcap=True, listen=None):
    return SimpleNamespace(
        ifaces={i.network_name: i for i in ifaces},
        iface=ifaces[default] if ifaces else None,
        use_npcap=use_npcap,
        use_pcap=use_pcap,
        L2listen=listen,
    )


class FakeSocket:
    def __init__(self):
        self.closed = False
        self.reads = 0

    def recv(self, *a):  # must never be called by the diagnostic
        self.reads += 1

    def close(self):
        self.closed = True


class FakePsutil:
    def __init__(self, stats=None, fail=False):
        self._stats = stats or {}
        self._fail = fail

    def net_if_stats(self):
        if self._fail:
            raise PermissionError("denied")
        return self._stats


def _loader(conf, version="2.8.0"):
    return lambda: (conf, version)


@pytest.fixture(autouse=True)
def _no_real_npcap_queries(monkeypatch):
    """Keep driver_status from touching the real Windows registry/service in tests."""
    real = diag.driver_status

    def fake(conf, system):
        if system == "Windows":
            ok = bool(conf.use_npcap)
            return diag.DriverStatus(
                name="Npcap", available=ok, version="Npcap 1.90" if ok else None,
                service_running=ok, admin_only=False, loopback_support=True,
                message=None if ok else "Npcap was not detected.",
            )  # fmt: skip
        return real(conf, system)

    monkeypatch.setattr(diag, "driver_status", fake)


# ----------------------------------------------------------------------------- happy path


def test_capture_available_opens_and_closes_without_reading():
    sockets = []

    def opener(iface):
        sockets.append((iface.name, FakeSocket()))
        return sockets[-1][1]

    conf = _conf(_iface("Wi-Fi", "UP+RUNNING+WIRELESS+OK"), _iface("Ethernet", "UP+DISCONNECTED"))
    report = run_diagnostics(
        scapy_loader=_loader(conf), psutil_module=FakePsutil(), opener=opener,
        platform_data=WINDOWS,
    )  # fmt: skip
    assert report.scapy.available and report.scapy.version == "2.8.0"
    assert report.driver.name == "Npcap" and report.driver.available
    assert report.capture_check.status == "available"
    assert report.capture_check.interface == "Wi-Fi"
    assert report.capture_available
    assert len(sockets) == 1 and sockets[0][1].closed and sockets[0][1].reads == 0


def test_specific_interface_is_used():
    opened = []
    conf = _conf(_iface("Wi-Fi"), _iface("Ethernet"))
    report = run_diagnostics(
        interface="Ethernet", scapy_loader=_loader(conf), psutil_module=FakePsutil(),
        opener=lambda i: opened.append(i.name) or FakeSocket(), platform_data=WINDOWS,
    )  # fmt: skip
    assert opened == ["Ethernet"] and report.capture_check.interface == "Ethernet"


def test_interface_listing_flags_and_no_addresses():
    conf = _conf(
        _iface("Wi-Fi", "UP+RUNNING+WIRELESS+OK"),
        _iface("Loopback Pseudo-Interface 1", "LOOPBACK+UP+RUNNING", ip=None),
    )
    ps = FakePsutil({"Wi-Fi": SimpleNamespace(isup=True), "Ghost": SimpleNamespace(isup=False)})
    report = run_diagnostics(
        check=False, scapy_loader=_loader(conf), psutil_module=ps, platform_data=WINDOWS
    )
    by_name = {i.name: i for i in report.interfaces}
    assert by_name["Wi-Fi"].is_wireless and by_name["Wi-Fi"].is_up and by_name["Wi-Fi"].has_ipv4
    assert by_name["Wi-Fi"].psutil_stats
    assert by_name["Loopback Pseudo-Interface 1"].is_loopback
    assert not by_name["Loopback Pseudo-Interface 1"].has_ipv4
    assert by_name["Ghost"].psutil_stats is True and by_name["Ghost"].description is None
    assert any("Ghost" in n and "not visible to Scapy" in n for n in report.notes)
    dumped = json.dumps(report.as_dict())
    assert "192.0.2.10" not in dumped and "00:11:22:33:44:55" not in dumped


@pytest.mark.parametrize(
    "ip, expected",
    [("192.0.2.10", True), ("127.0.0.1", True), ("169.254.7.7", False), ("0.0.0.0", False),
     (None, False), ("", False), ("fe80::1", False)],
)  # fmt: skip
def test_link_local_and_unspecified_addresses_are_not_usable(ip, expected):
    report = run_diagnostics(
        check=False, scapy_loader=_loader(_conf(_iface("Wi-Fi", ip=ip))),
        psutil_module=FakePsutil(), platform_data=WINDOWS,
    )  # fmt: skip
    assert report.interfaces[0].has_ipv4 is expected


def test_no_capture_check_never_opens_a_socket():
    def opener(_):
        raise AssertionError("must not open a socket")

    report = run_diagnostics(
        check=False, scapy_loader=_loader(_conf(_iface("Wi-Fi"))), psutil_module=FakePsutil(),
        opener=opener, platform_data=WINDOWS,
    )  # fmt: skip
    assert report.capture_check.status == "not_checked"


# ----------------------------------------------------------------------------- failures


def test_scapy_missing_is_reported_not_raised():
    def loader():
        raise ScapyUnavailableError("scapy_missing", "Scapy is not installed.")

    ps = FakePsutil({"Wi-Fi": SimpleNamespace(isup=True)})
    report = run_diagnostics(scapy_loader=loader, psutil_module=ps, platform_data=WINDOWS)
    assert not report.scapy.available and report.scapy.error_code == "scapy_missing"
    assert report.capture_check.status == "unavailable"
    assert report.capture_check.error_code == "scapy_missing"
    assert [i.name for i in report.interfaces] == ["Wi-Fi"]  # psutil still lists interfaces


def test_npcap_missing_reports_driver_and_skips_open():
    def opener(_):
        raise AssertionError("must not open without a driver")

    conf = _conf(_iface("Wi-Fi"), use_npcap=False, use_pcap=False)
    report = run_diagnostics(
        scapy_loader=_loader(conf), psutil_module=FakePsutil(), opener=opener,
        platform_data=WINDOWS,
    )  # fmt: skip
    assert not report.driver.available
    assert report.capture_check.error_code == "driver_missing"


@pytest.mark.parametrize(
    "exc",
    [
        PermissionError(errno.EPERM, "Operation not permitted"),
        OSError("Error opening adapter: Access is denied. (5)"),
        OSError(errno.EACCES, "Permission denied"),
    ],
)
def test_permission_errors_are_classified(exc):
    def opener(_):
        raise exc

    report = run_diagnostics(
        scapy_loader=_loader(_conf(_iface("Wi-Fi"))), psutil_module=FakePsutil(), opener=opener,
        platform_data=WINDOWS,
    )  # fmt: skip
    check = report.capture_check
    assert check.status == "unavailable" and check.error_code == "permission_denied"
    assert "administrator" in check.message.lower()


def test_unknown_interface_is_not_opened():
    def opener(_):
        raise AssertionError("must not open an unknown interface")

    report = run_diagnostics(
        interface="eth9", scapy_loader=_loader(_conf(_iface("Wi-Fi"))),
        psutil_module=FakePsutil(), opener=opener, platform_data=WINDOWS,
    )  # fmt: skip
    assert report.capture_check.error_code == "interface_not_found"


@pytest.mark.parametrize(
    "exc, code",
    [
        (OSError(errno.ENODEV, "No such device"), "interface_not_found"),
        (OSError("Error opening adapter: cannot find the device. (20)"), "interface_not_found"),
        (RuntimeError("wpcap.dll failed to load"), "driver_error"),
        (ValueError("something odd"), "capture_error"),
    ],
)  # fmt: skip
def test_other_errors_are_classified(exc, code):
    assert classify_capture_error(exc)[0] == code


def test_socket_close_failure_does_not_crash():
    class BadClose(FakeSocket):
        def close(self):
            raise OSError("close failed")

    report = run_diagnostics(
        scapy_loader=_loader(_conf(_iface("Wi-Fi"))), psutil_module=FakePsutil(),
        opener=lambda _: BadClose(), platform_data=WINDOWS,
    )  # fmt: skip
    assert report.capture_check.status == "available"


def test_psutil_failure_is_a_note_not_an_error():
    report = run_diagnostics(
        check=False, scapy_loader=_loader(_conf(_iface("Wi-Fi"))),
        psutil_module=FakePsutil(fail=True), platform_data=WINDOWS,
    )  # fmt: skip
    assert [i.name for i in report.interfaces] == ["Wi-Fi"]
    assert any("psutil" in n for n in report.notes)


def test_linux_raw_socket_mode_and_wsl_note():
    report = run_diagnostics(
        check=False, scapy_loader=_loader(_conf(_iface("eth0"), use_npcap=False, use_pcap=False)),
        psutil_module=FakePsutil(), platform_data=WSL,
    )  # fmt: skip
    assert report.driver.name == "raw sockets"
    assert "CAP_NET_RAW" in report.driver.message
    assert any("WSL" in n for n in report.notes)


# ----------------------------------------------------------------------------- inference stays off


def test_live_inference_always_reported_disabled(monkeypatch):
    monkeypatch.setenv("NIDS_LIVE_INFERENCE_ENABLED", "true")
    report = run_diagnostics(
        check=False, scapy_loader=_loader(_conf(_iface("Wi-Fi"))), psutil_module=FakePsutil(),
        platform_data=WINDOWS,
    )  # fmt: skip
    assert report.live_inference["enabled"] is False
    assert "cannot be derived from real traffic" in report.live_inference["reason"]


def test_diagnostic_module_does_not_import_the_model():
    import inspect

    source = inspect.getsource(diag)
    assert "model_loader" not in source and "InferenceService" not in source


# ----------------------------------------------------------------------------- CLI


@pytest.mark.parametrize(
    "status, argv, expected",
    [("available", [], 0), ("unavailable", [], 1), ("not_checked", ["--no-capture-check"], 0)],
)
def test_cli_exit_codes_and_json(monkeypatch, capsys, status, argv, expected):
    def fake_run(interface=None, check=True):
        return diag.DiagnosticReport(
            platform=WINDOWS,
            scapy=diag.ScapyStatus(True, "2.8.0"),
            driver=None,
            interfaces=[],
            capture_check=diag.CaptureCheck(status, "Wi-Fi"),
        )

    monkeypatch.setattr(diag, "run_diagnostics", fake_run)
    assert diag.main([*argv, "--json"]) == expected
    out = json.loads(capsys.readouterr().out)
    assert out["capture_check"]["status"] == status
    assert out["live_inference"]["enabled"] is False


def test_cli_scapy_missing_exit_code(monkeypatch, capsys):
    def fake_run(interface=None, check=True):
        return diag.DiagnosticReport(
            platform=WINDOWS, scapy=diag.ScapyStatus(False, None, "scapy_missing", "missing"),
            driver=None, interfaces=[], capture_check=diag.CaptureCheck("unavailable"),
        )  # fmt: skip

    monkeypatch.setattr(diag, "run_diagnostics", fake_run)
    assert diag.main([]) == 2
    assert "UNAVAILABLE" in capsys.readouterr().out
