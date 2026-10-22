"""Network-interface discovery with psutil (+ Scapy visibility when the capture extra is installed).

Reports names, state and counters only. IP and MAC addresses are not returned.
"""

from __future__ import annotations

from types import ModuleType
from typing import Any

from major_project.services import capture_diagnostics


def _psutil() -> ModuleType | None:
    try:
        import psutil
    except ImportError:
        return None
    return psutil


def _safe(fn) -> tuple[Any, str | None]:
    try:
        return fn(), None
    except Exception as exc:  # unsupported on this platform, permission, ...
        return None, type(exc).__name__


def discover_interfaces(
    psutil_module: ModuleType | None = None, scapy_loader=None
) -> dict[str, Any]:
    ps = psutil_module if psutil_module is not None else _psutil()
    notes: list[str] = []
    stats, counters = {}, {}
    if ps is None:
        notes.append("psutil is not installed; interface statistics are unavailable.")
    else:
        stats, err = _safe(ps.net_if_stats)
        if err:
            notes.append(f"Interface state unavailable ({err}).")
            stats = {}
        counters, err = _safe(lambda: ps.net_io_counters(pernic=True))
        if err:
            notes.append(f"Traffic counters unavailable ({err}).")
            counters = {}

    report = capture_diagnostics.run_diagnostics(
        check=False,
        psutil_module=ps,
        **({"scapy_loader": scapy_loader} if scapy_loader else {}),
    )
    names = list(dict.fromkeys([*stats.keys(), *(i.name for i in report.interfaces)]))
    diag = {i.name: i for i in report.interfaces}

    interfaces = []
    for name in names:
        st, io_ = stats.get(name), counters.get(name)
        d = diag.get(name)
        interfaces.append(
            {
                "name": name,
                "description": d.description if d else None,
                "is_up": bool(st.isup) if st is not None else (d.is_up if d else None),
                "speed_mbps": (st.speed or None) if st is not None else None,
                "mtu": st.mtu if st is not None else None,
                "is_loopback": d.is_loopback if d else "loopback" in name.lower(),
                "is_wireless": d.is_wireless if d else False,
                "has_ipv4": d.has_ipv4 if d else None,
                "visible_to_scapy": bool(report.scapy.available and d and d.visible_to_scapy),
                "counters": None if io_ is None else {
                    "bytes_sent": io_.bytes_sent, "bytes_recv": io_.bytes_recv,
                    "packets_sent": io_.packets_sent, "packets_recv": io_.packets_recv,
                    "errors_in": io_.errin, "errors_out": io_.errout,
                    "drops_in": io_.dropin, "drops_out": io_.dropout,
                },
            }
        )  # fmt: skip
    notes.extend(report.notes)
    return {
        "interfaces": interfaces,
        "scapy": report.scapy.__dict__,
        "driver": None if report.driver is None else report.driver.__dict__,
        "platform": report.platform,
        "notes": notes,
        "capture_note": (
            "'visible_to_scapy' means the interface can be selected for capture. Whether it can "
            "actually be opened is checked separately (POST /api/network/capture-check). Only "
            "capture traffic you are authorised to monitor."
        ),
    }
