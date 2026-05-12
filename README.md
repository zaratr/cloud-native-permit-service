# Cloud-Native Event System with eBPF Observability

## ?? 2026 Architecture Modernization
Application-level telemetry adds overhead and requires code changes. This project implements **eBPF (Extended Berkeley Packet Filter)** for zero-instrumentation observability.

### Key Features
1. **Kernel-Level Tracing:** Uses eBPF and cc to attach kprobes to network interfaces, tracing HTTP traffic and performance directly from the Linux kernel.
2. **Zero-Instrumentation:** Monitors microservice health, network latency, and packet drops without requiring a single tracing library inside the application code.
3. **Event-Driven Processing:** Acts as the core ingestion point for permit workflows, designed for high throughput and resilience.

## ??? Tech Stack
*   **Observability:** eBPF, bcc (BPF Compiler Collection)
*   **Architecture:** Event-Driven Microservices
*   **Language:** Python
