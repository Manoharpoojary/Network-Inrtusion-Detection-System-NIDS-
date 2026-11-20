"""Packet-header parsing and bidirectional flow aggregation (Scapy-based, header fields only).

Only these header fields are read: IP version/protocol, addresses (in memory, as part of the flow
key), ports, TCP flags and packet lengths. Payload bytes are never inspected, stored or logged.
Extracted flows carry no IP or MAC addresses.

Flow definition (documented because the training data does not specify one):

* key: (IP protocol, unordered pair of (address, port) endpoints), so both directions share a flow;
  the endpoint that sent the first packet is the "source".
* a flow ends after ``idle_timeout`` seconds without packets, after ``active_timeout`` seconds in
  total, when the flow table is full (oldest flow evicted), or at end of input.
* byte counts use the packet's on-the-wire length (``wirelen``, else captured length).
* payload length = transport payload size computed from header length fields (TCP/UDP/ICMP); the
  payload bytes themselves are never read. Used by the live-detection model's features.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

IP_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


class MalformedPacketError(ValueError):
    """The packet's headers could not be parsed consistently."""


@dataclass(frozen=True, slots=True)
class PacketMeta:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    ip_proto: int
    length: int
    tcp_flags: str = ""
    payload_len: int = 0  # transport payload bytes (from header length fields)


def ensure_scapy_layers() -> None:
    """Register Scapy's Ethernet/IP/TCP/UDP dissectors.

    Scapy binds IP to Ethernet only when ``scapy.layers.inet`` is imported. Without this, packets
    read or captured before that import are dissected as raw bytes and look like non-IP traffic.
    """
    import scapy.layers.inet
    import scapy.layers.inet6
    import scapy.layers.l2  # noqa: F401


def packet_meta(pkt: Any) -> PacketMeta | None:
    """Extract header metadata from a Scapy packet. ``None`` for non-IP packets."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    try:
        # Snaplen-truncated captures are fine: only headers are needed, and byte counts use the
        # on-the-wire length. A packet is malformed only if its headers cannot be dissected.
        if IP in pkt:
            ip = pkt[IP]
            proto, src, dst = int(ip.proto), str(ip.src), str(ip.dst)
        elif IPv6 in pkt:
            ip = pkt[IPv6]
            proto, src, dst = int(ip.nh), str(ip.src), str(ip.dst)
        else:
            return None

        sport = dport = 0
        flags = ""
        ip_payload = _ip_payload_len(ip)
        if TCP in pkt:
            tcp = pkt[TCP]
            sport, dport, flags = int(tcp.sport), int(tcp.dport), str(tcp.flags)
            payload = ip_payload - int(tcp.dataofs or 5) * 4
        elif UDP in pkt:
            udp = pkt[UDP]
            sport, dport = int(udp.sport), int(udp.dport)
            payload = (int(udp.len) - 8) if udp.len else ip_payload - 8
        elif proto in (6, 17):
            raise MalformedPacketError("transport header missing or truncated")
        elif ICMP not in pkt and proto == 1:
            raise MalformedPacketError("ICMP header missing")
        else:
            payload = ip_payload - 8 if proto in (1, 58) else ip_payload

        wire = getattr(pkt, "wirelen", None)
        length = int(wire) if wire else len(pkt)
        ts = float(pkt.time)
        if not math.isfinite(ts) or length <= 0:
            raise MalformedPacketError("invalid timestamp or length")
    except MalformedPacketError:
        raise
    except Exception as exc:  # scapy dissection errors on corrupt data
        raise MalformedPacketError(f"{type(exc).__name__}") from exc
    return PacketMeta(ts, src, dst, sport, dport, proto, length, flags, max(payload, 0))


def _ip_payload_len(ip: Any) -> int:
    """Bytes after the IP header, from the IPv4 total length / IPv6 payload length fields."""
    if hasattr(ip, "ihl"):  # IPv4
        total = int(ip.len) if ip.len else len(ip)
        return total - int(ip.ihl or 5) * 4
    plen = int(ip.plen) if ip.plen else len(ip) - 40
    return plen


@dataclass
class ExtractedFlow:
    """Measured flow statistics. No addresses."""

    ip_proto: int
    sport: int  # source = endpoint that sent the first packet
    dport: int
    first_seen: float
    last_seen: float
    pkts: int
    bytes: int
    spkts: int
    dpkts: int
    sbytes: int
    dbytes: int
    min_len: int
    max_len: int
    sum_sq: float
    tcp_flags: str
    end_reason: str
    # Payload-size and inter-arrival statistics (live-detection model features).
    fwd_payload: int = 0
    bwd_payload: int = 0
    payload_min: int = 0
    payload_max: int = 0
    payload_sum: float = 0.0
    payload_sum_sq: float = 0.0
    iat_count: int = 0
    iat_sum: float = 0.0
    iat_sum_sq: float = 0.0

    @property
    def dur(self) -> float:
        return max(self.last_seen - self.first_seen, 0.0)

    @property
    def mean_len(self) -> float:
        return self.bytes / self.pkts

    @property
    def std_len(self) -> float:
        variance = self.sum_sq / self.pkts - self.mean_len**2
        return math.sqrt(max(variance, 0.0))

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip_proto": self.ip_proto,
            "transport": IP_PROTO_NAMES.get(self.ip_proto, str(self.ip_proto)),
            "sport": self.sport,
            "dport": self.dport,
            "first_seen_utc": datetime.fromtimestamp(self.first_seen, UTC).isoformat(),
            "dur": self.dur,
            "pkts": self.pkts,
            "bytes": self.bytes,
            "spkts": self.spkts,
            "dpkts": self.dpkts,
            "sbytes": self.sbytes,
            "dbytes": self.dbytes,
            "pkt_len_min": self.min_len,
            "pkt_len_max": self.max_len,
            "pkt_len_mean": self.mean_len,
            "pkt_len_std": self.std_len,
            "tcp_flags_seen": self.tcp_flags,
            "end_reason": self.end_reason,
        }


@dataclass
class _FlowState:
    initiator: tuple[str, int]
    ip_proto: int
    sport: int
    dport: int
    first: float
    last: float
    pkts: int = 0
    bytes: int = 0
    spkts: int = 0
    dpkts: int = 0
    sbytes: int = 0
    dbytes: int = 0
    min_len: int = 1 << 30
    max_len: int = 0
    sum_sq: float = 0.0
    flags: set[str] = field(default_factory=set)
    fwd_payload: int = 0
    bwd_payload: int = 0
    payload_min: int = 1 << 30
    payload_max: int = 0
    payload_sum: float = 0.0
    payload_sum_sq: float = 0.0
    prev_ts: float | None = None
    iat_count: int = 0
    iat_sum: float = 0.0
    iat_sum_sq: float = 0.0

    def add(self, m: PacketMeta) -> None:
        forward = (m.src, m.sport) == self.initiator
        if self.prev_ts is not None:
            iat = max(m.ts - self.prev_ts, 0.0)
            self.iat_count += 1
            self.iat_sum += iat
            self.iat_sum_sq += iat * iat
        self.prev_ts = m.ts
        if forward:
            self.fwd_payload += m.payload_len
        else:
            self.bwd_payload += m.payload_len
        self.payload_min = min(self.payload_min, m.payload_len)
        self.payload_max = max(self.payload_max, m.payload_len)
        self.payload_sum += m.payload_len
        self.payload_sum_sq += float(m.payload_len) ** 2
        self.last = max(self.last, m.ts)
        self.pkts += 1
        self.bytes += m.length
        if forward:
            self.spkts += 1
            self.sbytes += m.length
        else:
            self.dpkts += 1
            self.dbytes += m.length
        self.min_len = min(self.min_len, m.length)
        self.max_len = max(self.max_len, m.length)
        self.sum_sq += float(m.length) ** 2
        self.flags.update(m.tcp_flags)

    def finish(self, reason: str) -> ExtractedFlow:
        return ExtractedFlow(
            ip_proto=self.ip_proto, sport=self.sport, dport=self.dport, first_seen=self.first,
            last_seen=self.last, pkts=self.pkts, bytes=self.bytes, spkts=self.spkts,
            dpkts=self.dpkts, sbytes=self.sbytes, dbytes=self.dbytes, min_len=self.min_len,
            max_len=self.max_len, sum_sq=self.sum_sq, tcp_flags="".join(sorted(self.flags)),
            end_reason=reason, fwd_payload=self.fwd_payload, bwd_payload=self.bwd_payload,
            payload_min=self.payload_min if self.pkts else 0, payload_max=self.payload_max,
            payload_sum=self.payload_sum, payload_sum_sq=self.payload_sum_sq,
            iat_count=self.iat_count, iat_sum=self.iat_sum, iat_sum_sq=self.iat_sum_sq,
        )  # fmt: skip


class FlowAggregator:
    def __init__(
        self, idle_timeout: float = 60.0, active_timeout: float = 300.0, max_active: int = 50_000
    ):
        if idle_timeout <= 0 or active_timeout <= 0 or max_active < 1:
            raise ValueError("timeouts must be positive and max_active >= 1")
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_active = max_active
        self._flows: OrderedDict[tuple, _FlowState] = OrderedDict()  # least recently active first
        self.evicted_for_capacity = 0

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    @staticmethod
    def _key(m: PacketMeta) -> tuple:
        a, b = (m.src, m.sport), (m.dst, m.dport)
        return (m.ip_proto, a, b) if a <= b else (m.ip_proto, b, a)

    def add(self, m: PacketMeta) -> list[ExtractedFlow]:
        done = self._expire(m.ts)
        key = self._key(m)
        state = self._flows.get(key)
        if state is not None and m.ts - state.first > self.active_timeout:
            done.append(self._flows.pop(key).finish("active_timeout"))
            state = None
        if state is None:
            if len(self._flows) >= self.max_active:
                _, oldest = self._flows.popitem(last=False)
                done.append(oldest.finish("capacity"))
                self.evicted_for_capacity += 1
            state = _FlowState((m.src, m.sport), m.ip_proto, m.sport, m.dport, m.ts, m.ts)
            self._flows[key] = state
        else:
            self._flows.move_to_end(key)
        state.add(m)
        return done

    def expire(self, now: float) -> list[ExtractedFlow]:
        """Finish flows idle at time ``now`` (used by live capture when no packets arrive)."""
        return self._expire(now)

    def _expire(self, now: float) -> list[ExtractedFlow]:
        done = []
        while self._flows:
            key, state = next(iter(self._flows.items()))
            if now - state.last <= self.idle_timeout:
                break
            del self._flows[key]
            done.append(state.finish("idle_timeout"))
        return done

    def flush(self, reason: str = "end_of_input") -> list[ExtractedFlow]:
        done = [s.finish(reason) for s in self._flows.values()]
        self._flows.clear()
        return done
