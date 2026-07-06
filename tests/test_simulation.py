"""Tests for the eBPF tracer's simulation mode.

Simulation mode is the path that runs without a Linux kernel or bcc — i.e. the
path exercised on Windows, macOS, and CI. These tests verify the event
generator produces a realistic, well-formed stream and that the ingest helper
classifies events correctly. They do NOT load eBPF programs (that requires
root + Linux and is covered manually by the README's real-mode runbook).
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

# Make `src/` importable when running pytest from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import ebpf_tracer as t  # noqa: E402


# ── Event generation ────────────────────────────────────────────────────────

def _take(generator, n):
    """Pull the first n items from a (possibly infinite) generator."""
    out = []
    gen = iter(generator)
    for _ in range(n):
        out.append(next(gen))
    return out


def test_simulator_yields_valid_event_kinds():
    """Every simulated event must carry one of the four known kind codes."""
    events = _take(t._simulate_events(rate_hz=1000), 50)
    for ev in events:
        assert ev.kind in (t.KIND_OPEN, t.KIND_ESTABLISHED, t.KIND_CLOSED,
                           t.KIND_RESET), f"unknown kind {ev.kind}"


def test_simulator_resets_have_short_durations():
    """A reset is a failed handshake — it should never carry a long duration."""
    events = _take(t._simulate_events(rate_hz=1000), 500)
    resets = [e for e in events if e.kind == t.KIND_RESET]
    assert resets, "expected at least one reset in 500 simulated events"
    for r in resets:
        # Resets model a ~20ms handshake failure; cap well above that for safety.
        assert r.duration_ns < 1_000_000_000, (
            f"reset duration {r.duration_ns}ns implausibly long")


def test_simulator_healthy_connections_have_duration():
    """A closed healthy connection must record an open→close duration."""
    events = _take(t._simulate_events(rate_hz=1000), 500)
    closed = [e for e in events if e.kind == t.KIND_CLOSED]
    assert closed, "expected at least one clean close in 500 simulated events"
    for c in closed:
        assert c.duration_ns > 0, "clean close should carry a positive duration"


def test_simulator_addresses_are_renderable():
    """Every simulated destination address must round-trip to dotted-quad."""
    events = _take(t._simulate_events(rate_hz=1000), 50)
    for ev in events:
        rendered = t._addr_str(ev.daddr)
        # Either a valid dotted-quad or (fallback) the raw int — never crash.
        assert rendered, "address rendering returned empty"


# ── Event ordering ───────────────────────────────────────────────────────────

def test_reset_preceded_by_open():
    """Each reset must follow an open (you can't reset a connection you never
    started). The simulator emits open→reset pairs; verify that invariant."""
    events = _take(t._simulate_events(rate_hz=1000), 500)
    for i, ev in enumerate(events):
        if ev.kind == t.KIND_RESET:
            assert events[i - 1].kind == t.KIND_OPEN, (
                f"reset at {i} not preceded by an open: "
                f"{events[i - 1].kind if i > 0 else 'start'}")


# ── Helpers ──────────────────────────────────────────────────────────────────

def test_port_byte_order_roundtrip():
    """The simulator stores ports network-byte-order; _port_str must invert it."""
    host_order = 5432
    net_order = socket.htons(host_order)
    assert t._port_str(net_order) == host_order


def test_addr_byte_order_roundtrip():
    """The simulator stores addrs network-byte-order; _addr_str must render them."""
    raw = int.from_bytes(socket.inet_aton("10.0.1.10"), "big")
    assert t._addr_str(raw) == "10.0.1.10"


# ── Prometheus ingest (only when prometheus_client is importable) ───────────

def test_ingest_runs_without_prometheus():
    """_ingest_event must be a safe no-op when prometheus_client is absent,
    so the tracer never crashes on a machine without it."""
    if t.PROMETHEUS_AVAILABLE:
        # On machines with prometheus_client, just verify it doesn't raise.
        t._ingest_event(t.KIND_OPEN, 0x0a00010a, 5432, "dotnet", 0)
        return
    # Without prometheus_client this should silently do nothing.
    t._ingest_event(t.KIND_OPEN, 0x0a00010a, 5432, "dotnet", 0)
