# eBPF Connection-Lifecycle Tracer

Zero-instrumentation **TCP connection-health** monitoring for cloud-native
services. This tracer hooks the Linux kernel's TCP state machine directly and
surfaces connection opens, closes, and resets as Prometheus metrics — no SDK
calls, no log statements, no sidecars.

It is the **connection-health** counterpart to a latency tracer: where latency
monitoring answers *"how long did a socket round-trip take?"*, this answers
*"are connections succeeding — and which dependency is failing?"*.

## Why this exists

During a connection-related incident, the signal you need first is the **reset
rate** — a burst of TCP resets is the fingerprint of a cascading connection
failure, a rejected handshake, or a dependency that just went unhealthy.
Application logs and SDK-based metrics arrive late (they require the app to
notice and emit) and miss the connections that never made it to user space at
all. eBPF sees every connection from the kernel, regardless of language or
runtime.

This maps directly to reliability engineering mandates — *reduce blast radius,
detect failures early, auto-recover* — because connection resets are often the
first observable symptom of a failing dependency.

## What it measures

| Signal | Source | How |
|---|---|---|
| Connection opens | outbound `connect()` | `tcp_v4_connect` kprobe |
| Resets / handshake failures | close-with-error transitions | `tcp_set_state` kprobe |
| Active in-flight connections | open minus close bookkeeping | derived in user space |
| Established duration (open→close) | tracked per-socket | `BPF_HASH` + close timestamp |
| State transitions | every TCP state change | `tcp_set_state` kprobe |

### Prometheus metrics (all prefixed `conn_`)

| Metric | Type | Labels |
|---|---|---|
| `conn_opens_total` | counter | dest_addr, dest_port, process |
| `conn_resets_total` | counter | dest_addr, dest_port, process |
| `conn_state_transitions_total` | counter | kind |
| `conn_active` | gauge | — |
| `conn_established_duration_seconds` | histogram | process |

The **reset rate** (`rate(conn_resets_total[1m])`) is the headline alerting
signal. See the Grafana dashboard in `observability/`.

## Architecture

```
app process ──┐                     ┌──────────────────────────────────────┐
              │                     │           Linux Kernel               │
dotnet / func ├────────────────────▶│  tcp_v4_connect  kprobe              │
              │                     │  tcp_set_state   kprobe              │
node / python ┘                     │         │                            │
                                    │  ┌──────▼───────────────────┐        │
                                    │  │  BPF ring buffer          │        │
                                    │  └──────────────┬───────────┘        │
                                    └─────────────────┼────────────────────┘
                                                      │ user-space reader
                                              ┌───────▼────────┐
                                              │  ebpf_tracer   │
                                              │  Prometheus /  │
                                              │  metrics       │
                                              └───────┬────────┘
                                                      │
                                              ┌───────▼────────┐
                                              │ Prometheus /   │
                                              │ Grafana        │
                                              └────────────────┘
```

## Quick start

### Prerequisites

**Real mode (Linux only — kernel 5.8+ for BPF ring buffers):**
```bash
# Ubuntu / Debian
sudo apt install bpfcc-tools linux-headers-$(uname -r)
pip install -r requirements.txt
```

**Simulation mode (any platform — Windows, macOS, CI):**
```bash
pip install prometheus_client
```

### Run the tracer

```bash
# Real eBPF mode (requires root or CAP_BPF)
sudo python3 src/ebpf_tracer.py 8765

# Simulation mode (no root / no kernel needed — for dev, demo, and CI)
python3 src/ebpf_tracer.py 8765 --simulate --rate 50
```

Prometheus metrics are served at `http://localhost:8765/metrics`.

### Import the Grafana dashboard

In Grafana → Dashboards → Import → upload
`observability/grafana-dashboard.json`. Datasource: your Prometheus instance
scraping `:8765`.

### Run the tests

```bash
pip install pytest prometheus_client
pytest tests/ -v
```

Tests exercise the simulation event generator and the byte-order / ingest
helpers — they run anywhere Python runs, no kernel required.

## Simulation mode

Because eBPF requires a Linux kernel, the tracer ships with a first-class
**simulation mode** (`--simulate`, or automatic when `bcc` is unavailable) that
generates a realistic connection workload: mostly healthy open→established→close
cycles against simulated peers (a database, a cache, an HTTPS API), punctuated
by occasional single resets and rare cascading-failure bursts.

This lets the metrics pipeline, dashboard, and alerting rules be developed and
verified on Windows, macOS, or CI without root or a kernel. The simulated
metrics are structurally identical to real-mode output.

## How it relates to a latency tracer

This project is intentionally scoped to **connection health** (open / close /
reset / duration). A sibling tracer that measures per-socket round-trip latency
via `tcp_sendmsg` / `tcp_cleanup_rbuf` kprobes lives in the
[azure-permit-processing-pipeline](https://github.com/zaratr/azure-permit-processing-pipeline)
observability layer. Together they give a complete zero-instrumentation
picture: *are connections succeeding?* (this project) and *when they succeed,
how fast are they?* (the latency tracer).

## Tech stack

* **Observability:** eBPF, bcc (BPF Compiler Collection), Prometheus
* **Kernel hooks:** kprobes on `tcp_v4_connect` and `tcp_set_state`
* **Language:** Python 3.10+
