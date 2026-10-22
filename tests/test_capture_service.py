"""Live-capture lifecycle with a FAKE sniffer and SYNTHETIC packet metadata.

No capture device, driver, network access or administrator rights are used. Addresses come from
the reserved documentation ranges and must not appear in status output.
"""

import errno
import threading
import time

import pytest

from major_project.services.capture_service import (
    CaptureError,
    CaptureLimits,
    LiveCaptureManager,
)
from major_project.services.flow_features import MalformedPacketError, PacketMeta

A, B = "192.0.2.10", "198.51.100.20"


def meta(i=0, ts=None, sport=40000, dport=80, src=A, dst=B, length=100):
    return PacketMeta(
        ts if ts is not None else time.time(), src, dst, sport, dport, 6, length, "PA"
    )


class FakeSniffer:
    """Mimics scapy.AsyncSniffer: delivers packets from a thread until stopped."""

    def __init__(self, prn, packets=(), sync_packets=(), fail_in_thread=None, fail_after=None):
        self.prn = prn
        self.packets = list(packets)
        self.sync_packets = list(sync_packets)  # delivered inside start(), before the worker runs
        self.fail_in_thread = fail_in_thread
        self.fail_after = fail_after
        self.exception = None
        self.running = False
        self.stopped = threading.Event()
        self.stop_calls = 0
        self.thread = None

    def start(self):
        self.running = True
        for p in self.sync_packets:
            self.prn(p)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        if self.fail_in_thread is not None:
            self.exception = self.fail_in_thread
            self.running = False
            return
        for p in self.packets:
            if self.stopped.is_set():
                return
            self.prn(p)
        if self.fail_after is not None:
            time.sleep(self.fail_after[0])
            self.exception = self.fail_after[1]
            return
        self.stopped.wait()

    def stop(self, join=True):
        self.stop_calls += 1
        if not self.running:
            raise RuntimeError("Not running")
        self.stopped.set()
        self.running = False
        if join and self.thread:
            self.thread.join(2)


class RecordingValidator:
    """Stands in for InferenceService; records calls so tests can prove nothing is scored."""

    def __init__(self, inference):
        self.inference = inference
        self.calls = []

    def validate_frame(self, frame, row_offset=0):
        self.calls.append("validate_frame")
        return self.inference.validate_frame(frame, row_offset)

    def __getattr__(self, name):  # any prediction method would be recorded and refused
        self.calls.append(name)
        raise AssertionError(f"capture must not call {name}")


@pytest.fixture
def made(bundle, service):
    created = {}
    finished = []

    def factory_for(**sniffer_kwargs):
        def factory(iface, bpf, prn):
            created["sniffer"] = FakeSniffer(prn, **sniffer_kwargs)
            created["iface"], created["bpf"] = iface, bpf
            return created["sniffer"]

        return factory

    def build(limits=None, resolver=lambda name: {"name": name}, meta_fn=lambda p: p, **kw):
        validator = RecordingValidator(service)
        mgr = LiveCaptureManager(
            limits or CaptureLimits(startup_grace_seconds=0.05, join_timeout_seconds=5),
            feature_order=list(bundle.schema.feature_order),
            reference=None,
            validator=validator,
            live_inference_enabled=True,  # even when enabled, incompatible flows are not scored
            sniffer_factory=factory_for(**kw),
            interface_resolver=resolver,
            meta_fn=meta_fn,
            on_finish=lambda session, report: finished.append((session, report)),
        )
        return mgr, created, finished, validator

    return build


def wait_for(predicate, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_start_status_stop_lifecycle(made):
    packets = [meta(), meta(src=B, dst=A, sport=80, dport=40000), meta(), meta(dport=53)]
    mgr, created, finished, validator = made(packets=packets)
    assert mgr.status()["state"] == "stopped"

    st = mgr.start("Wi-Fi", "tcp or udp", 30)
    assert st["state"] == "running" and created["bpf"] == "tcp or udp"
    assert wait_for(lambda: mgr.status()["session"]["counters"]["packets_queued"] == 4)

    final = mgr.stop()
    assert final["state"] == "stopped" and final["session"]["stop_reason"] == "user_request"
    c = final["session"]["counters"]
    assert c["packets_seen"] == 4 and c["ip_packets"] == 4 and c["dropped_queue_full"] == 0
    assert c["flows_emitted"] == 2  # TCP conversation + DNS-port flow
    assert created["sniffer"].stop_calls == 1
    assert final["predictions"] is None
    assert final["compatibility"]["compatible"] is False
    assert final["live_inference"]["enabled"] is False
    assert final["live_inference"]["gate_allowed"] is False
    assert A not in str(final) and B not in str(final)

    [(session, report)] = finished
    assert session.state == "stopped" and report["compatible"] is False
    assert set(validator.calls) <= {"validate_frame"}  # schema check only, never prediction


def test_only_one_session_at_a_time(made):
    mgr, *_ = made()
    mgr.start("Wi-Fi")
    with pytest.raises(CaptureError) as exc:
        mgr.start("Wi-Fi")
    assert exc.value.status_code == 409 and exc.value.code == "capture_busy"
    mgr.stop()


def test_stop_without_session(made):
    mgr, *_ = made()
    with pytest.raises(CaptureError) as exc:
        mgr.stop()
    assert exc.value.code == "capture_not_running"


def test_unknown_interface_does_not_start(made):
    def resolver(name):
        raise CaptureError(404, "interface_not_found", "not visible")

    mgr, created, finished, _ = made(resolver=resolver)
    with pytest.raises(CaptureError) as exc:
        mgr.start("eth9")
    assert exc.value.code == "interface_not_found"
    assert mgr.status()["state"] == "stopped" and "sniffer" not in created and finished == []


@pytest.mark.parametrize(
    "error, code",
    [
        (PermissionError(errno.EPERM, "Operation not permitted"), "permission_denied"),
        (OSError("Error opening adapter: Access is denied. (5)"), "permission_denied"),
        (OSError(errno.ENODEV, "No such device"), "interface_not_found"),
    ],
)
def test_sniffer_start_failure_is_reported_and_persisted(made, error, code):
    mgr, _, finished, _ = made(fail_in_thread=error)
    with pytest.raises(CaptureError) as exc:
        mgr.start("Wi-Fi")
    assert exc.value.status_code == 503 and exc.value.code == code
    st = mgr.status()
    assert st["state"] == "error" and st["session"]["error"]["code"] == code
    assert len(finished) == 1 and finished[0][0].state == "error"
    # A new session can be started after an error.
    mgr.sniffer_factory = lambda iface, bpf, prn: FakeSniffer(prn)
    assert mgr.start("Wi-Fi")["state"] == "running"
    mgr.stop()


def test_factory_failure_when_driver_missing(made, bundle):
    mgr, *_ = made()

    def no_driver(iface, bpf, prn):
        raise CaptureError(503, "scapy_missing", "Scapy is not installed")

    mgr.sniffer_factory = no_driver
    with pytest.raises(CaptureError) as exc:
        mgr.start("Wi-Fi")
    assert exc.value.code == "scapy_missing" and mgr.state == "error"


def test_queue_overflow_is_counted_not_silent(made):
    limits = CaptureLimits(queue_size=10, startup_grace_seconds=0.01)
    mgr, *_ = made(limits=limits, sync_packets=[meta(i, sport=1000 + i) for i in range(25)])
    mgr.start("Wi-Fi")
    final = mgr.stop()
    c = final["session"]["counters"]
    assert c["packets_seen"] == 25
    assert c["packets_queued"] == 10 and c["dropped_queue_full"] == 15
    assert c["flows_emitted"] == 10  # every queued packet was drained and aggregated


def test_malformed_and_non_ip_packets_are_counted(made):
    def meta_fn(p):
        if p == "bad":
            raise MalformedPacketError("broken header")
        if p == "arp":
            return None
        return p

    mgr, *_ = made(meta_fn=meta_fn, packets=[meta(), "bad", "arp", "bad"])
    mgr.start("Wi-Fi")
    assert wait_for(lambda: mgr.status()["session"]["counters"]["packets_seen"] == 4)
    c = mgr.stop()["session"]["counters"]
    assert (c["ip_packets"], c["malformed_packets"], c["non_ip_packets"]) == (1, 2, 1)


def test_max_duration_stops_automatically(made):
    limits = CaptureLimits(max_duration_seconds=1, startup_grace_seconds=0.01)
    mgr, _, finished, _ = made(limits=limits, packets=[meta()])
    mgr.start("Wi-Fi")
    assert wait_for(lambda: mgr.state == "stopped", timeout=5)
    st = mgr.status()
    assert st["session"]["stop_reason"] == "max_duration" and len(finished) == 1


def test_requested_duration_is_capped(made):
    mgr, *_ = made(limits=CaptureLimits(max_duration_seconds=5, startup_grace_seconds=0.01))
    st = mgr.start("Wi-Fi", max_duration=3600)
    assert st["session"]["max_duration_seconds"] == 5
    mgr.stop()


def test_sniffer_error_while_running_stops_session(made):
    mgr, _, finished, _ = made(packets=[meta()], fail_after=(0.2, OSError("adapter removed")))
    mgr.start("Wi-Fi")
    assert wait_for(lambda: mgr.state == "error", timeout=5)
    st = mgr.status()
    assert st["session"]["stop_reason"] == "sniffer_error"
    assert st["session"]["counters"]["packets_seen"] == 1
    assert finished and finished[0][0].state == "error"


def test_idle_flows_expire_while_running(made):
    old = time.time() - 120  # older than the 60 s idle timeout
    mgr, *_ = made(packets=[meta(ts=old), meta(ts=old, dport=53)])
    mgr.start("Wi-Fi")
    assert wait_for(lambda: mgr.status()["session"]["counters"]["flows_emitted"] == 2, timeout=5)
    assert mgr.status()["session"]["active_flows"] == 0
    mgr.stop()


def test_shutdown_stops_active_session(made):
    mgr, created, finished, _ = made(packets=[meta()])
    mgr.start("Wi-Fi")
    mgr.shutdown()
    assert (
        mgr.state == "stopped" and mgr.status()["session"]["stop_reason"] == "application_shutdown"
    )
    assert created["sniffer"].stop_calls == 1 and len(finished) == 1
    mgr.shutdown()  # idempotent when nothing is running


def test_reset_clears_finished_session_only(made):
    mgr, _, finished, _ = made(packets=[meta(), meta(dport=53)])
    assert mgr.reset()["state"] == "stopped"  # nothing to reset is fine
    mgr.start("Wi-Fi")
    with pytest.raises(CaptureError) as exc:
        mgr.reset()
    assert exc.value.code == "capture_busy" and mgr.state == "running"
    mgr.stop()
    assert mgr.status()["session"]["counters"]["packets_seen"] == 2
    cleared = mgr.reset()
    assert cleared == mgr.status()
    assert cleared["state"] == "stopped" and cleared["session"] is None
    assert len(finished) == 1  # the persisted session is not touched
    assert mgr.start("Wi-Fi")["session"]["counters"]["packets_seen"] >= 0  # can start again
    mgr.stop()
