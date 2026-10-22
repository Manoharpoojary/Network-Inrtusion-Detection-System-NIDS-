"""Offline PCAP / PCAPNG analysis: stream packets, aggregate flows, report compatibility.

Packets are read from memory (no temporary files). Flows are never scored by the model unless the
compatibility report passes and live inference is explicitly enabled (see ``compatibility``).
"""

from __future__ import annotations

import io
import logging
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass

from major_project.services.flow_features import (
    ExtractedFlow,
    FlowAggregator,
    MalformedPacketError,
    PacketMeta,
    ensure_scapy_layers,
    packet_meta,
)

logger = logging.getLogger(__name__)

CAPTURE_MAGICS = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # pcap, microsecond timestamps
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",  # pcap, nanosecond timestamps
    b"\x0a\x0d\x0d\x0a",                      # pcapng
}  # fmt: skip


class PcapRejectedError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class CaptureLibraryUnavailableError(RuntimeError):
    """Scapy (the optional ``capture`` extra) is not installed."""


@dataclass
class PcapStats:
    packets_read: int = 0
    ip_packets: int = 0
    non_ip_packets: int = 0
    malformed_packets: int = 0
    packet_limit_reached: bool = False
    read_error: str | None = None  # file ended or became unreadable part-way through
    truncated_records: int = 0  # records shorter than their header claims (reported by Scapy)
    flows_extracted: int = 0
    flows_not_analyzed: int = 0  # beyond the analysis cap; counted, not silently dropped
    flows_evicted_for_capacity: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def scapy_reader(data: bytes) -> Iterable:
    try:
        from scapy.utils import PcapReader

        ensure_scapy_layers()
    except ImportError as exc:
        raise CaptureLibraryUnavailableError(
            "Scapy is not installed; install the optional extra: uv sync --extra capture"
        ) from exc
    try:
        return PcapReader(io.BytesIO(data))
    except Exception as exc:
        raise PcapRejectedError(
            400, "invalid_capture_file", "Not a readable PCAP/PCAPNG file."
        ) from exc


class _ScapyPcapWarningCounter(logging.Handler):
    """Counts Scapy's 'Pcap: ...' warnings (e.g. truncated records) raised in this thread.

    Scapy reports a truncated record as a log warning instead of an exception.
    """

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.thread = threading.get_ident()
        self.truncated = 0

    def emit(self, record: logging.LogRecord) -> None:
        if record.thread == self.thread and "truncated" in record.getMessage():
            self.truncated += 1


@contextmanager
def _count_scapy_warnings() -> Iterator[_ScapyPcapWarningCounter]:
    counter = _ScapyPcapWarningCounter()
    scapy_logger = logging.getLogger("scapy.runtime")
    scapy_logger.addHandler(counter)
    try:
        yield counter
    finally:
        scapy_logger.removeHandler(counter)


def check_magic(data: bytes) -> None:
    if len(data) < 24:
        raise PcapRejectedError(400, "invalid_capture_file", "File is too small to be a capture.")
    if data[:4] not in CAPTURE_MAGICS:
        raise PcapRejectedError(
            400, "invalid_capture_file", "Not a PCAP or PCAPNG file (unrecognised header)."
        )


def analyze_capture(
    data: bytes,
    max_packets: int,
    max_flows_analyzed: int,
    idle_timeout: float,
    active_timeout: float,
    max_active_flows: int,
    reader_factory: Callable[[bytes], Iterable] = scapy_reader,
    meta_fn: Callable[[object], PacketMeta | None] = packet_meta,
) -> tuple[list[ExtractedFlow], PcapStats]:
    check_magic(data)
    stats = PcapStats()
    aggregator = FlowAggregator(idle_timeout, active_timeout, max_active_flows)
    flows: list[ExtractedFlow] = []

    def keep(done: list[ExtractedFlow]) -> None:
        for flow in done:
            stats.flows_extracted += 1
            if len(flows) < max_flows_analyzed:
                flows.append(flow)
            else:
                stats.flows_not_analyzed += 1

    reader = reader_factory(data)
    iterator = iter(reader)
    with _count_scapy_warnings() as warnings_seen:
        _read_all(iterator, stats, meta_fn, aggregator, keep, max_packets, reader)
    stats.truncated_records = warnings_seen.truncated
    keep(aggregator.flush())
    stats.flows_evicted_for_capacity = aggregator.evicted_for_capacity
    logger.info("capture analysed", extra={"records": stats.packets_read})
    return flows, stats


def _read_all(iterator, stats, meta_fn, aggregator, keep, max_packets, reader) -> None:
    try:
        while True:
            try:
                pkt = next(iterator)
            except StopIteration:
                break
            except Exception as exc:  # truncated or corrupt record: stop, keep what was read
                stats.read_error = f"{type(exc).__name__} after {stats.packets_read} packets"
                break
            if stats.packets_read >= max_packets:
                stats.packet_limit_reached = True
                break
            stats.packets_read += 1
            try:
                meta = meta_fn(pkt)
            except MalformedPacketError:
                stats.malformed_packets += 1
                continue
            if meta is None:
                stats.non_ip_packets += 1
                continue
            stats.ip_packets += 1
            keep(aggregator.add(meta))
    finally:
        close = getattr(reader, "close", None)
        if close is not None:
            close()
