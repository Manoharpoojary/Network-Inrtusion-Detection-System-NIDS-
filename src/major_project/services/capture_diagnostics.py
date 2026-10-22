"""Network-capture diagnostic: is Scapy importable, which interfaces exist, can we open one?

Run it from the project root:

    uv run --extra capture python -m major_project.services.capture_diagnostics
    uv run --extra capture python -m major_project.services.capture_diagnostics --interface Wi-Fi
    uv run --extra capture python -m major_project.services.capture_diagnostics --json

The capture check opens a single listen socket on one interface and closes it straight away. No
packet is read and nothing is stored. The diagnostic never starts continuous capture, and it never
sends traffic to the intrusion model: inference on live traffic stays disabled because the model's
features cannot be derived from real flows (docs/MODEL_CARD.md, docs/IMPLEMENTATION_PLAN.md §7.5).

Only the interface name, description, index and up/loopback/wireless flags are reported. MAC and IP
addresses are not printed.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import ipaddress
import json
import os
import platform
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from types import ModuleType
from typing import Any, Literal

LIVE_INFERENCE_REASON = (
    "The model's training features (e.g. spkts == dpkts == pkts // 2, min/max/stddev "
    "definitions) cannot be derived from real traffic. See docs/MODEL_CARD.md."
)

CaptureStatus = Literal["available", "unavailable", "not_checked"]


@dataclass
class ScapyStatus:
    available: bool
    version: str | None = None
    error_code: str | None = None
    message: str | None = None


@dataclass
class DriverStatus:
    name: str  # "Npcap" on Windows, "libpcap / raw sockets" elsewhere
    available: bool
    version: str | None = None
    service_running: bool | None = None
    admin_only: bool | None = None
    loopback_support: bool | None = None
    message: str | None = None


@dataclass
class InterfaceInfo:
    name: str
    description: str | None
    index: int | None
    is_up: bool | None
    is_loopback: bool
    is_wireless: bool
    has_ipv4: bool  # a usable IPv4 (not 0.0.0.0 or 169.254/16 link-local)
    psutil_stats: bool  # psutil reports this interface (statistics available)


@dataclass
class CaptureCheck:
    status: CaptureStatus
    interface: str | None = None
    error_code: str | None = None
    message: str | None = None


@dataclass
class DiagnosticReport:
    platform: dict[str, Any]
    scapy: ScapyStatus
    driver: DriverStatus | None
    interfaces: list[InterfaceInfo]
    capture_check: CaptureCheck
    live_inference: dict[str, Any] = field(
        default_factory=lambda: {"enabled": False, "reason": LIVE_INFERENCE_REASON}
    )
    notes: list[str] = field(default_factory=list)

    @property
    def capture_available(self) -> bool:
        return self.capture_check.status == "available"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScapyUnavailableError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ----------------------------------------------------------------------------- environment


def _is_admin(system: str) -> bool | None:
    try:
        if system == "Windows":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return None


def platform_info() -> dict[str, Any]:
    uname = platform.uname()
    return {
        "system": uname.system,
        "release": uname.release,
        "python": platform.python_version(),
        "is_wsl": "microsoft" in uname.release.lower(),
        "is_admin": _is_admin(uname.system),
    }


def load_scapy() -> tuple[Any, str]:
    """Import Scapy fully (``scapy.all`` initialises the platform layer and interface list)."""
    try:
        import scapy
        from scapy.all import conf
    except ImportError as exc:
        raise ScapyUnavailableError(
            "scapy_missing",
            "Scapy is not installed. Install the optional extra: uv sync --extra capture",
        ) from exc
    except Exception as exc:  # broken install, missing platform libraries
        raise ScapyUnavailableError(
            "scapy_import_error", f"Scapy failed to initialise: {type(exc).__name__}: {exc}"
        ) from exc
    return conf, str(getattr(scapy, "VERSION", "unknown"))


# ----------------------------------------------------------------------------- driver


def driver_status(conf: Any, system: str) -> DriverStatus:
    if system == "Windows":
        status = DriverStatus(name="Npcap", available=bool(getattr(conf, "use_npcap", False)))
        try:
            import scapy.arch.windows as win
            from scapy.libs.winpcapy import pcap_lib_version

            status.service_running = bool(win.pcap_service_status())
            status.version = pcap_lib_version().decode(errors="replace")
            status.admin_only = win._get_npcap_config("AdminOnly") == 1
            status.loopback_support = win._get_npcap_config("LoopbackSupport") == 1
        except Exception as exc:  # Npcap missing or registry keys unreadable
            status.message = f"Could not query Npcap details: {type(exc).__name__}"
        if not status.available:
            status.message = (
                "Npcap was not detected. Install it from https://npcap.com with "
                "'WinPcap API-compatible mode', then restart this program."
            )
        elif status.service_running is False:
            status.message = "The Npcap service is not running (run: sc start npcap, as admin)."
        return status

    use_pcap = bool(getattr(conf, "use_pcap", False))
    return DriverStatus(
        name="libpcap" if use_pcap else "raw sockets",
        available=True,
        message=None
        if use_pcap
        else "Using Linux raw sockets: capture needs root or CAP_NET_RAW/CAP_NET_ADMIN.",
    )


# ----------------------------------------------------------------------------- interfaces


def list_interfaces(
    conf: Any, psutil_module: ModuleType | None
) -> tuple[list[InterfaceInfo], list[str]]:
    notes: list[str] = []
    stats: dict[str, Any] = {}
    if psutil_module is not None:
        try:
            stats = psutil_module.net_if_stats()
        except Exception as exc:
            notes.append(f"psutil could not read interface statistics: {type(exc).__name__}")

    result: list[InterfaceInfo] = []
    seen: set[str] = set()
    for iface in _scapy_interfaces(conf):
        name = str(getattr(iface, "name", "") or getattr(iface, "network_name", ""))
        if not name or name in seen:
            continue
        seen.add(name)
        flags = str(getattr(iface, "flags", "") or "")
        ps = stats.get(name)
        result.append(
            InterfaceInfo(
                name=name,
                description=getattr(iface, "description", None),
                index=_int_or_none(getattr(iface, "index", None)),
                is_up=bool(ps.isup) if ps is not None else ("UP" in flags.split("+") or None),
                is_loopback="LOOPBACK" in flags.upper() or "loopback" in name.lower(),
                is_wireless="WIRELESS" in flags.upper(),
                has_ipv4=_usable_ipv4(getattr(iface, "ip", None)),
                psutil_stats=ps is not None,
            )
        )
    # Interfaces psutil knows about but Scapy cannot see (usually: not capturable).
    for name, ps in stats.items():
        if name not in seen:
            result.append(
                InterfaceInfo(
                    name=name,
                    description=None,
                    index=None,
                    is_up=bool(ps.isup),
                    is_loopback="loopback" in name.lower() or name == "lo",
                    is_wireless=False,
                    has_ipv4=False,
                    psutil_stats=True,
                )
            )
            notes.append(f"Interface {name!r} is not visible to Scapy and cannot be captured.")
    return result, notes


def _scapy_interfaces(conf: Any) -> list[Any]:
    ifaces = getattr(conf, "ifaces", None)
    if ifaces is None:
        return []
    try:
        return list(ifaces.values())
    except Exception:
        return []


def _usable_ipv4(value: Any) -> bool:
    """True for an assigned IPv4 address; False for none, 0.0.0.0 or link-local (169.254/16).

    Windows gives disconnected adapters a 169.254.x.x address, which says nothing about capture.
    """
    try:
        addr = ipaddress.IPv4Address(str(value))
    except ValueError:
        return False
    return not (addr.is_unspecified or addr.is_link_local)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------- capture check


def classify_capture_error(exc: BaseException) -> tuple[str, str]:
    """Map an exception from opening a capture socket to (error_code, user-facing message)."""
    text = f"{type(exc).__name__}: {exc}"
    lowered = text.lower()
    err = getattr(exc, "errno", None)
    if (
        isinstance(exc, PermissionError)
        or err in (errno.EPERM, errno.EACCES)
        or any(k in lowered for k in ("access is denied", "permission", "operation not permitted"))
    ):
        return (
            "permission_denied",
            "Permission denied opening the capture device. On Windows, Npcap may be installed "
            "with 'Restrict Npcap driver's access to Administrators only': run as administrator "
            "or reinstall Npcap without that option. On Linux, run as root or grant "
            f"CAP_NET_RAW/CAP_NET_ADMIN. ({text})",
        )
    if err == errno.ENODEV or any(
        k in lowered for k in ("no such device", "cannot find the device", "not found")
    ):
        return "interface_not_found", f"The capture device could not be opened. ({text})"
    if any(k in lowered for k in ("npcap", "winpcap", "libpcap", "wpcap", "pcap")):
        return "driver_error", f"The packet-capture driver reported an error. ({text})"
    return "capture_error", f"Opening the capture socket failed. ({text})"


def _resolve_interface(conf: Any, name: str | None) -> Any:
    if name is None:
        return getattr(conf, "iface", None)
    for iface in _scapy_interfaces(conf):
        if name in {
            getattr(iface, "name", None),
            getattr(iface, "network_name", None),
            getattr(iface, "description", None),
        }:
            return iface
    return None


def _default_opener(conf: Any) -> Callable[[Any], Any]:
    listen = getattr(conf, "L2listen", None)
    if listen is None:
        raise ScapyUnavailableError("driver_missing", "Scapy has no layer-2 listen socket.")
    return lambda iface: listen(iface=iface)


def check_capture(
    conf: Any,
    interface: str | None,
    driver: DriverStatus | None,
    opener: Callable[[Any], Any] | None = None,
) -> CaptureCheck:
    """Open one listen socket on ``interface`` (default: Scapy's default) and close it at once."""
    if driver is not None and not driver.available:
        return CaptureCheck("unavailable", interface, "driver_missing", driver.message)
    iface = _resolve_interface(conf, interface)
    if iface is None:
        return CaptureCheck(
            "unavailable",
            interface,
            "interface_not_found",
            f"Interface {interface!r} is not known to Scapy." if interface
            else "Scapy has no default interface.",
        )  # fmt: skip
    label = str(getattr(iface, "name", iface))
    try:
        open_socket = opener or _default_opener(conf)
        sock = open_socket(iface)
    except ScapyUnavailableError as exc:
        return CaptureCheck("unavailable", label, exc.code, str(exc))
    except Exception as exc:
        code, message = classify_capture_error(exc)
        return CaptureCheck("unavailable", label, code, message)
    with contextlib.suppress(Exception):  # the check already succeeded
        sock.close()
    return CaptureCheck(
        "available",
        label,
        None,
        "A capture socket was opened and closed without reading packets. This does not "
        "authorise monitoring this network: capture only traffic you are permitted to inspect.",
    )


# ----------------------------------------------------------------------------- orchestration


def run_diagnostics(
    interface: str | None = None,
    check: bool = True,
    scapy_loader: Callable[[], tuple[Any, str]] = load_scapy,
    psutil_module: ModuleType | None = None,
    opener: Callable[[Any], Any] | None = None,
    platform_data: dict[str, Any] | None = None,
) -> DiagnosticReport:
    plat = platform_data or platform_info()
    if psutil_module is None:
        try:
            import psutil as psutil_module
        except ImportError:
            psutil_module = None

    try:
        conf, version = scapy_loader()
    except ScapyUnavailableError as exc:
        interfaces, notes = list_interfaces(None, psutil_module)
        return DiagnosticReport(
            platform=plat,
            scapy=ScapyStatus(False, None, exc.code, str(exc)),
            driver=None,
            interfaces=interfaces,
            capture_check=CaptureCheck("unavailable", interface, exc.code, str(exc)),
            notes=notes,
        )

    driver = driver_status(conf, plat["system"])
    interfaces, notes = list_interfaces(conf, psutil_module)
    if plat.get("is_wsl"):
        notes.append(
            "Running inside WSL: only the WSL VM's virtual network is visible, not the Windows "
            "host's Wi-Fi/Ethernet traffic. Run the diagnostic on Windows to use Npcap."
        )
    capture = (
        check_capture(conf, interface, driver, opener)
        if check
        else CaptureCheck("not_checked", interface, None, "Capture check skipped.")
    )
    return DiagnosticReport(
        platform=plat,
        scapy=ScapyStatus(True, version),
        driver=driver,
        interfaces=interfaces,
        capture_check=capture,
        notes=notes,
    )


def format_report(report: DiagnosticReport) -> str:
    p, s, d, c = report.platform, report.scapy, report.driver, report.capture_check
    lines = [
        f"Platform      : {p['system']} {p['release']} (admin={p['is_admin']}, wsl={p['is_wsl']})",
        "Scapy         : " + (f"OK {s.version}" if s.available else f"UNAVAILABLE - {s.message}"),
    ]
    if d is not None:
        lines.append(
            f"Driver        : {d.name} available={d.available} version={d.version} "
            f"service_running={d.service_running} admin_only={d.admin_only} "
            f"loopback={d.loopback_support}"
        )
        if d.message:
            lines.append(f"                {d.message}")
    lines.append(f"Interfaces    : {len(report.interfaces)}")
    for i in report.interfaces:
        state = {True: "up", False: "down", None: "?"}[i.is_up]
        tags = ",".join(
            t
            for t, on in (
                ("loopback", i.is_loopback),
                ("wireless", i.is_wireless),
                ("ipv4", i.has_ipv4),
            )
            if on
        )
        lines.append(f"  - {i.name:<36} {state:<5} {tags:<22} {i.description or ''}")
    lines.append(
        f"Capture check : {c.status.upper()} on {c.interface!r}"
        + (f" [{c.error_code}]" if c.error_code else "")
    )
    if c.message:
        lines.append(f"                {c.message}")
    lines.append(f"Live inference: DISABLED - {report.live_inference['reason']}")
    lines.extend(f"Note          : {n}" for n in report.notes)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Scapy/Npcap packet-capture availability.")
    parser.add_argument("--interface", help="interface name to test (default: Scapy's default)")
    parser.add_argument("--no-capture-check", action="store_true", help="only list interfaces")
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)

    report = run_diagnostics(interface=args.interface, check=not args.no_capture_check)
    print(json.dumps(report.as_dict(), indent=2) if args.json else format_report(report))
    if not report.scapy.available:
        return 2
    if args.no_capture_check:
        return 0
    return 0 if report.capture_available else 1


if __name__ == "__main__":
    sys.exit(main())
