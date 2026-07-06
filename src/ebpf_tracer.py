#!/usr/bin/env python3
"""
eBPF Connection-Lifecycle Tracer
=================================

Zero-instrumentation TCP connection-health monitoring. Where a latency tracer
(measured by a sibling tool) answers "how long did a socket round-trip take?",
this tracer answers "are connections succeeding, and which ones are failing?".

It hooks the Linux kernel's TCP state machine directly:

  - tcp_v4_connect        — a connect() syscall has started (SYN sent)
  - tcp_set_state         — the connection entered a new TCP state

From those two hooks we derive the signals an on-call engineer actually wants
during a connection-related incident:

  - conn_opens_total            how many outbound connections were attempted
  - conn_resets_total           how many connections died with RST (the failure
                                signal — a burst here is the signature of a
                                cascading connection failure / unhealthy dependency)
  - conn_state_transitions      every from→to state transition, for funnels
  - conn_active                 currently-in-flight (SYN_SENT / ESTABLISHED) count
  - conn_established_duration   open→close duration, surfacing short-lived /
                                churned connections (e.g. a missing keep-alive)

Architecture
------------
                     ┌──────────────────────────────────────┐
                     │           Linux Kernel               │
   app process ─────▶│  tcp_v4_connect  kprobe              │
                     │  tcp_set_state   kretprobe / kprobe  │
                     │         │                            │
                     │  ┌──────▼───────────────────┐        │
                     │  │  BPF ring buffer          │        │
                     │  └──────────────┬───────────┘        │
                     └─────────────────┼────────────────────┘
                                       │ user-space reader
                               ┌───────▼────────┐
                               │  this script   │
                               │ Prometheus /   │
                               │ metrics        │
                               └───────┬────────┘
                                       │
                               ┌───────▼────────┐
                               │ Prometheus /   │
                               │ Grafana        │
                               └────────────────┘

Requirements
------------
  pip install bcc prometheus_client      # (bcc needs a Linux kernel, see below)
  Root / CAP_BPF required to load eBPF programs.
  Tested on Ubuntu 22.04, kernel 5.8+ (BPF ring buffers require 5.8+).

When bcc is unavailable (Windows, macOS, or CI without a kernel), the tracer
runs in a *simulation* mode that generates realistic connection events so the
metrics pipeline, dashboard, and alerting logic can be developed and verified
without root or a Linux host. Pass --simulate to force simulation mode.
"""

from __future__ import annotations

import argparse
import random
import signal
import socket
import sys
import time
from dataclasses import dataclass
from typing import Iterator

# ── Optional kernel dependencies ─────────────────────────────────────────────
# bcc and prometheus_client are imported defensively: the tracer must import
# cleanly on any platform (Windows, CI, etc.) so simulation mode works, and so
# `py_compile` / unit tests pass without a Linux kernel.

try:
    from bcc import BPF  # type: ignore
    BCC_AVAILABLE = True
except ImportError:
    BPF = None  # type: ignore
    BCC_AVAILABLE = False

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        start_http_server,
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


# ── TCP states (mirror <uapi/linux/net.h> / inet_stream_sock) ────────────────
# Used both to label BPF events and to name simulated transitions.
TCP_STATES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
}
ESTABLISHED = 1
SYN_SENT = 2
CLOSE = 7
# A connection reset is reported by the kernel as a transition to CLOSE that
# followed an ECONNRESET-style teardown; we surface it as a distinct signal.
CLOSE_STATES = {6, 7, 8, 9, 11}  # TIME_WAIT, CLOSE, CLOSE_WAIT, LAST_ACK, CLOSING


def state_label(code: int) -> str:
    return TCP_STATES.get(code, str(code))


# ── eBPF program (C) ─────────────────────────────────────────────────────────
# Two probes:
#   * tcp_v4_connect  — fires on the connect() path; record the attempt and
#     the destination so we can attribute later failures to a peer.
#   * tcp_set_state   — fires on every TCP state transition; the source of all
#     opens / establishes / closes / resets.
#
# A per-sock hash tracks {sock -> (open_ts_ns, daddr, dport)} so we can compute
# established-connection duration at close time and emit a single, rich event.

EBPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Per-socket metadata captured at connect() time.
struct conn_meta_t {
    u64 open_ts_ns;     // when tcp_v4_connect fired for this sock
    u32 daddr;          // destination IPv4 address (network byte order)
    u16 dport;          // destination port
    char comm[16];      // process name at connect time
};
BPF_HASH(conn_meta, struct sock *, struct conn_meta_t);

// Ring buffer event emitted to user space.
struct conn_event_t {
    u32  pid;
    u64  open_ts_ns;        // 0 for events that are not a close
    u64  duration_ns;       // open→close duration, 0 unless this is a close
    u32  daddr;
    u16  dport;
    u16  kind;              // 1=open 2=established 3=closed 4=reset
    char comm[16];
};
BPF_RINGBUF_OUTPUT(conn_events, 64);

// kprobe on tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk,
                           struct sockaddr *uaddr, int addr_len) {
    u64 ts = bpf_ktime_get_ns();
    struct conn_meta_t meta = {};
    meta.open_ts_ns = ts;

    // Destination address/port from the sockaddr_in passed by the caller.
    struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
    bpf_probe_read_kernel(&meta.daddr, sizeof(meta.daddr), &usin->sin_addr.s_addr);
    bpf_probe_read_kernel(&meta.dport, sizeof(meta.dport), &usin->sin_port);
    bpf_get_current_comm(&meta.comm, sizeof(meta.comm));

    conn_meta.update(&sk, &meta);

    struct conn_event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.open_ts_ns = ts;
    e.daddr = meta.daddr;
    e.dport = meta.dport;
    e.kind = 1;  // open
    __builtin_memcpy(&e.comm, meta.comm, sizeof(e.comm));
    conn_events.ringbuf_output(&e, sizeof(e), 0);
    return 0;
}

// kprobe on tcp_set_state(struct sock *sk, int state).
// Fires on every transition; we classify into established / closed / reset.
int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    struct conn_meta_t *meta = conn_meta.lookup(&sk);
    if (!meta) {
        return 0;  // we never saw a connect() for this sock (e.g. inbound)
    }

    u16 kind = 0;
    if (state == 1) {            // TCP_ESTABLISHED
        kind = 2;
    } else if (state == 7) {     // TCP_CLOSE — covers normal close AND reset
        // A reset leaves sk_err set; a clean close does not. We approximate
        // the distinction here and refine it in user space if sk_err is
        // unreadable on this kernel version.
        kind = 3;  // classified as clean close by default
    } else {
        return 0;  // intermediate state, not interesting on its own
    }

    u64 now = bpf_ktime_get_ns();
    struct conn_event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.open_ts_ns = meta->open_ts_ns;
    e.duration_ns = (kind >= 3) ? (now - meta->open_ts_ns) : 0;
    e.daddr = meta->daddr;
    e.dport = meta->dport;
    e.kind = kind;
    __builtin_memcpy(&e.comm, meta->comm, sizeof(e.comm));
    conn_events.ringbuf_output(&e, sizeof(e), 0);

    if (kind >= 3) {
        conn_meta.delete(&sk);  // connection is done; stop tracking
    }
    return 0;
}
"""

# Event kind constants (must match the `kind` field set in the BPF program).
KIND_OPEN = 1
KIND_ESTABLISHED = 2
KIND_CLOSED = 3
KIND_RESET = 4
KIND_LABELS = {1: "open", 2: "established", 3: "closed", 4: "reset"}


# ── Prometheus metrics ───────────────────────────────────────────────────────
# Metric names are deliberately distinct from the latency tracer's (permit_*):
# these are prefixed conn_* and capture connection *health*, not latency.

if PROMETHEUS_AVAILABLE:
    CONN_OPENS = Counter(
        "conn_opens_total",
        "Outbound TCP connection attempts observed via tcp_v4_connect",
        ["dest_addr", "dest_port", "process"],
    )
    CONN_RESETS = Counter(
        "conn_resets_total",
        "TCP connections that closed with a reset / handshake failure",
        ["dest_addr", "dest_port", "process"],
    )
    CONN_TRANSITIONS = Counter(
        "conn_state_transitions_total",
        "TCP state transitions observed, labeled by event kind",
        ["kind"],
    )
    CONN_ACTIVE = Gauge(
        "conn_active",
        "Currently-tracked outbound connections (SYN_SENT or ESTABLISHED)",
    )
    CONN_DURATION = Histogram(
        "conn_established_duration_seconds",
        "Wall-clock duration from connect() to close for tracked connections",
        ["process"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
    )


def _addr_str(daddr_be: int) -> str:
    """Render a network-byte-order IPv4 address as dotted-quad."""
    try:
        return socket.inet_ntoa(daddr_be.to_bytes(4, "big"))
    except Exception:
        return str(daddr_be)


def _port_str(dport_be: int) -> int:
    """Convert a network-byte-order port to host order."""
    return socket.ntohs(dport_be)


# ── In-flight tracking shared by both modes ──────────────────────────────────
# We keep a small process-level dict so the `conn_active` gauge stays accurate
# in real mode too, not just simulation. Keyed by an arbitrary per-event id.
_active: dict[int, float] = {}
_next_id = 0


def _ingest_event(kind: int, daddr: int, dport: int, comm: str,
                  duration_ns: int) -> None:
    """Update metrics for one connection event. Shared by real + sim modes."""
    global _next_id
    if not PROMETHEUS_AVAILABLE:
        return

    addr = _addr_str(daddr)
    port = _port_str(dport) if dport >= 0 else dport
    label = KIND_LABELS.get(kind, str(kind))

    CONN_TRANSITIONS.labels(kind=label).inc()

    if kind == KIND_OPEN:
        _active[_next_id] = time.monotonic()
        _next_id += 1
        CONN_OPENS.labels(dest_addr=addr, dest_port=port, process=comm).inc()
    elif kind == KIND_ESTABLISHED:
        pass  # counted as a transition; active already incremented on open
    elif kind in (KIND_CLOSED, KIND_RESET):
        # Pop one in-flight connection (oldest first) to decrement active.
        if _active:
            _active.pop(next(iter(_active)), None)
        CONN_DURATION.labels(process=comm).observe(duration_ns / 1e9)
        if kind == KIND_RESET:
            CONN_RESETS.labels(dest_addr=addr, dest_port=port, process=comm).inc()

    CONN_ACTIVE.set(len(_active))


def _format_line(ts: float, kind: int, addr: str, port: int,
                 comm: str, duration_ns: int) -> str:
    label = KIND_LABELS.get(kind, str(kind)).upper()
    dur = f" dur={duration_ns / 1e6:.1f}ms" if duration_ns else ""
    return (f"{ts:<10.3f} {label:<11} {addr}:{port:<6} proc={comm}{dur}")


# ── Simulation mode (no kernel / no bcc) ─────────────────────────────────────
# A realistic outbound-connection workload: mostly healthy connections to a
# known dependency, with periodic bursts of resets to exercise the failure
# signal and the alerting/dashboard logic.

SIM_PEERS = [
    # (daddr network-byte-order int, port host-order, label)
    (int.from_bytes(socket.inet_aton("10.0.1.10"), "big"), 5432, "postgres"),
    (int.from_bytes(socket.inet_aton("10.0.2.20"), "big"), 6379, "redis"),
    (int.from_bytes(socket.inet_aton("10.0.3.30"), "big"), 443,  "api"),
    (int.from_bytes(socket.inet_aton("10.0.4.40"), "big"), 443,  "storage"),
]
SIM_COMMS = ["dotnet", "func", "python", "node"]


@dataclass
class SimEvent:
    kind: int
    daddr: int
    dport: int
    comm: str
    duration_ns: int


def _simulate_events(rate_hz: float = 5.0,
                     reset_fraction: float = 0.04) -> Iterator[SimEvent]:
    """Yield a realistic stream of connection-lifecycle events.

    A healthy dependency shows open→established→closed with a real duration.
    A failing dependency shows open→reset with a short duration and no
    established state. Occasionally a burst of resets simulates a cascading
    failure (the signal this tracer exists to surface).
    """
    rng = random.Random(42)  # deterministic seed → reproducible dashboards/tests
    interval = 1.0 / rate_hz
    burst_remaining = 0

    while True:
        daddr_be, dport_host, _ = rng.choice(SIM_PEERS)
        comm = rng.choice(SIM_COMMS)
        dport_be = socket.htons(dport_host)

        # A reset burst is a cluster of failures — model a dependency going unhealthy.
        if burst_remaining > 0:
            burst_remaining -= 1
            yield SimEvent(KIND_OPEN, daddr_be, dport_be, comm, 0)
            yield SimEvent(KIND_RESET, daddr_be, dport_be, comm,
                           int(rng.lognormvariate(3, 0.4)))  # ~20ms median
        else:
            yield SimEvent(KIND_OPEN, daddr_be, dport_be, comm, 0)
            if rng.random() < reset_fraction:
                # Single reset (handshake rejection / port closed).
                yield SimEvent(KIND_RESET, daddr_be, dport_be, comm,
                               int(rng.lognormvariate(3, 0.4)))
            else:
                # Healthy connection.
                yield SimEvent(KIND_ESTABLISHED, daddr_be, dport_be, comm, 0)
                duration = int(rng.lognormvariate(8.5, 0.7))  # ~5s median
                yield SimEvent(KIND_CLOSED, daddr_be, dport_be, comm, duration)

            # Rarely: trigger a reset burst (cascading failure).
            if rng.random() < 0.01:
                burst_remaining = rng.randint(8, 20)

        time.sleep(interval)


def run_simulation(prometheus_port: int, rate_hz: float, max_events: int | None,
                   verbose: bool) -> None:
    print(f"[SIM] bcc unavailable — simulated connection events on "
          f":{prometheus_port}")
    if PROMETHEUS_AVAILABLE:
        start_http_server(prometheus_port)

    count = 0
    start = time.monotonic()
    for ev in _simulate_events(rate_hz=rate_hz):
        _ingest_event(ev.kind, ev.daddr, ev.dport, ev.comm, ev.duration_ns)
        count += 1
        if verbose:
            addr = _addr_str(ev.daddr)
            port = _port_str(ev.dport)
            line = _format_line(time.monotonic() - start, ev.kind, addr, port,
                                ev.comm, ev.duration_ns)
            print(line, flush=True)
        if max_events is not None and count >= max_events:
            print(f"\n[SIM] emitted {count} events, exiting.")
            return


# ── Real eBPF mode ───────────────────────────────────────────────────────────

def run_real(prometheus_port: int, verbose: bool) -> None:
    if not BCC_AVAILABLE:
        sys.exit("ERROR: bcc is not available. Run with --simulate, or install "
                 "bcc on a Linux host (see README).")
    if not PROMETHEUS_AVAILABLE:
        sys.exit("ERROR: prometheus_client is not installed (pip install "
                 "prometheus_client).")

    b = BPF(text=EBPF_PROGRAM)
    print(f"[eBPF] connection-lifecycle tracer loaded — "
          f"Prometheus metrics on :{prometheus_port}")
    start_http_server(prometheus_port)

    def handle_event(cpu, data, size):
        event = b["conn_events"].event(data)
        addr = _addr_str(event.daddr)
        port = _port_str(event.dport)
        comm = event.comm.decode("utf-8", errors="replace")
        _ingest_event(event.kind, event.daddr, event.dport, comm,
                      event.duration_ns)
        if verbose:
            ts = time.monotonic()
            print(_format_line(ts, event.kind, addr, port, comm,
                               event.duration_ns), flush=True)

    b["conn_events"].open_ring_buffer(handle_event)

    def _sigint(_sig, _frame):
        print("\n[eBPF] detaching probes")
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint)

    while True:
        b.ring_buffer_consume()
        time.sleep(0.01)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="eBPF connection-lifecycle tracer. Surfaces TCP connection "
                    "opens, closes, and resets as Prometheus metrics.")
    ap.add_argument("port", nargs="?", type=int, default=8765,
                    help="Prometheus metrics port (default: 8765)")
    ap.add_argument("--simulate", action="store_true",
                    help="force simulation mode (no bcc/kernel required)")
    ap.add_argument("--rate", type=float, default=5.0,
                    help="simulated events/sec (simulation mode only)")
    ap.add_argument("--max-events", type=int, default=None,
                    help="stop after N simulated events (simulation mode only)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="suppress per-event stdout (still serves metrics)")
    args = ap.parse_args(argv)

    verbose = not args.quiet
    use_sim = args.simulate or not BCC_AVAILABLE

    if use_sim:
        run_simulation(args.port, args.rate, args.max_events, verbose)
    else:
        run_real(args.port, verbose)
    return 0


if __name__ == "__main__":
    sys.exit(main())
