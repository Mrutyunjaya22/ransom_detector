# System Architecture Manual: Comprehensive Project Understanding Guide

This document provides a systematic, engineering-first mental model of the **AI-Powered Behavioral Ransomware Detection & SOC Triage Platform (EDR)**. It explains the system's design philosophy, architectural decomposition, threat lifecycle, mathematical scoring engine, and component interaction map.

> [!TIP]
> For a full visual flowchart and role-based reading paths across all project documentation, refer to the **[Documentation Roadmap & Information Flow Matrix](file:///d:/ransom_web/ransom_detector/DOCUMENTATION_FLOW.md)**.


---

## 1. The Human Body Analogy (System Mental Model)

To understand this platform systematically, visualize it as an autonomous biological immune system:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           SYSTEM MENTAL MODEL                           │
├─────────────────┬───────────────────────────┬───────────────────────────┤
│ Biological Part │ Platform Component        │ Operational Responsibility│
├─────────────────┼───────────────────────────┼───────────────────────────┤
│ 👁️ Senses        │ agent/edr_agent.py        │ Watches file writes, CPU, │
│                 │ core/canary.py            │ and process forks.        │
├─────────────────┼───────────────────────────┼───────────────────────────┤
│ 🧠 Brain         │ core/engine.py            │ Scores behavioral vectors │
│                 │ models/rf_classifier.pkl  │ (Entropy + Heuristics + ML│
├─────────────────┼───────────────────────────┼───────────────────────────┤
│ 🦾 Reflex (Hands)│ backend/mitigation.py     │ Freezes thread scheduling │
│                 │                           │ and terminates malware.   │
├─────────────────┼───────────────────────────┼───────────────────────────┤
│ 📚 Memory        │ backend/database.py       │ Records persistent alerts,│
│                 │ backend/repository.py     │ reports, and scan history.│
├─────────────────┼───────────────────────────┼───────────────────────────┤
│ 📡 Nervous Syst.│ backend/grpc_server.py    │ Sub-second binary transport│
│                 │ backend/websocket_manager │ between sensors and SOC.  │
├─────────────────┼───────────────────────────┼───────────────────────────┤
│ 🔬 Adaptation    │ mlops/retrain_pipeline.py │ Retrains on analyst labels│
│                 │ backend/mlops_router.py   │ with live hot-reloading.  │
├─────────────────┼───────────────────────────┼───────────────────────────┤
│ 📊 Visual Cockpit│ ransomweb/ (React 19)    │ Human-in-the-loop triage, │
│                 │                           │ dials, and report exports.│
└─────────────────┴───────────────────────────┴───────────────────────────┘
```

---

## 2. System Decomposition: The 7 Functional Tiers

```mermaid
graph TD
    subgraph T1 ["Tier 1: Endpoint Sensors & Traps"]
        Agent["Sensor Agent (agent/edr_agent.py)"]
        Canary["Canary Trap Manager (core/canary.py)"]
        IoC["Pre-Encryption IoC Auditor (core/ioc_auditor.py)"]
    end

    subgraph T2 ["Tier 2: Ingestion & Transport"]
        gRPC["gRPC Server :50051 (backend/grpc_server.py)"]
        WS["WebSocket Hub :8000/ws/soc (backend/websocket_manager.py)"]
    end

    subgraph T3 ["Tier 3: Behavioral Detection Core"]
        Engine["Behavioral Engine (core/engine.py)"]
        ML["Random Forest Model (models/rf_classifier.pkl)"]
        Scanner["Streaming File Scanner (backend/scan_router.py)"]
    end

    subgraph T4 ["Tier 4: Active Defense & Containment"]
        Mitigator["ProcessMitigator (backend/mitigation.py)"]
    end

    subgraph T5 ["Tier 5: Relational State & Persistence"]
        Repo["EDRRepository (backend/repository.py)"]
        DB[(Async SQLite / Postgres edr_storage.db)]
    end

    subgraph T6 ["Tier 6: Continuous MLOps"]
        MLOps["Retraining Engine (mlops/retrain_pipeline.py)"]
        MLRouter["MLOps Router (backend/mlops_router.py)"]
    end

    subgraph T7 ["Tier 7: Human SOC Triage"]
        UI["SOC Dashboard :3000 (ransomweb/)"]
    end

    T1 -->|gRPC TelemetryBatch| T2
    T2 --> T3
    T3 -->|Risk >= 0.80| T4
    T1 -.->|Tripwire Tamper / IoC Sabotage| T4
    T4 -->|Directives over gRPC| T1
    T3 --> T5
    T4 --> T5
    T2 -->|Real-Time Push| T7
    T7 -->|Analyst Labels (TP/FP)| T6
    T6 -->|Hot-Reload Weights| T3
```

---

## 3. The Lifecycle of a Threat: Step-by-Step Data Flow

How an infected process is identified and neutralized in **sub-second latency**:

```text
[Step 1: Inception]
Malware starts ──> Attacker runs 'vssadmin delete shadows /all /quiet'
                    │
                    ▼
[Step 2: Proactive Detection]
core/ioc_auditor.py detects administrative sabotage pattern (MITRE T1490)
    │
    ├──> Direct Trigger: backend/mitigation.py immediately kills PID (Containment!)
    └──> Or if missed, malware proceeds to touch directory files.

                    │
                    ▼
[Step 3: Tripwire Activation]
Malware scans directory alphabetically ──> Encrypts '!00_passwords_vault.xlsx'
    │
    ├──> core/canary.py checks SHA-256 hash mismatch
    └──> Immediate Tripwire Killswitch: process terminated in 0ms!

                    │
                    ▼
[Step 4: Behavioral Vectorization]
If malware attacks random files ──> agent/edr_agent.py captures FileEvent stream
    │
    ├──> Computes Shannon entropy per file (bits/byte)
    ├──> Records rename velocity (.docx -> .locked)
    └──> Packages into TelemetryBatch and streams over gRPC (Port 50051)

                    │
                    ▼
[Step 5: Central Dual-Scoring Engine]
backend/grpc_server.py feeds core/engine.py sliding window (10s buffer)
    │
    ├──> Rule Layer: Checks entropy >= 7.5 + write rate >= 3 + extension change
    ├──> ML Layer: RandomForestClassifier evaluates 9-dimensional vector
    └──> Combined Risk Score: (0.5 * RuleScore) + (0.5 * MLScore) = 0.92

                    │
                    ▼
[Step 6: Active Containment Execution]
Risk >= 0.80 threshold reached!
    │
    ├──> backend/mitigation.py discovers entire process tree recursively
    ├──> Calls process.suspend() on all threads (0ms remaining I/O)
    ├──> Dispatches SIGTERM followed by SIGKILL escalation
    └──> Streams MitigationDirective back to endpoint over gRPC

                    │
                    ▼
[Step 7: SOC Broadcast & Forensic Archival]
    │
    ├──> backend/repository.py writes Alert and Incident Report to edr_storage.db
    ├──> backend/websocket_manager.py pushes real-time alert to SOC dashboard
    └──> Analyst views event timeline and exports JSON forensic report.

                    │
                    ▼
[Step 8: MLOps Retraining Loop]
Analyst verifies alert as True Positive ──> Clicks feedback in dashboard
    │
    ├──> backend/mlops_router.py records feedback
    ├──> mlops/retrain_pipeline.py retrains model with weighted sample
    └──> Hot-reloads updated model weights in memory with zero downtime!
```

---

## 4. Mathematical Detection & Scoring Model

### 4.1 Shannon Information Entropy
Entropy measures the average degree of uncertainty or randomness in a byte stream (range: $0.00$ to $8.00$ bits per byte).

$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the empirical probability of byte value $i$ occurring in the sample:
- **Plaintext text / source code**: $3.00 - 4.50$ bits/byte (redundant character distributions).
- **Compiled binaries**: $5.50 - 6.80$ bits/byte.
- **Ransomware Ciphertext (AES-256 / ChaCha20)**: **$7.60 - 7.99$ bits/byte** (statistically indistinguishable from random noise).

### 4.2 The 9-Dimensional Behavioral Feature Vector
The engine extracts these 9 signals from every process inside a $10$-second sliding window:
1. $x_1$: `file_op_rate` (file mutations per second)
2. $x_2$: `mean_entropy` (average entropy of touched files)
3. $x_3$: `high_entropy_fraction` (fraction of files with $H \ge 7.50$)
4. $x_4$: `ext_change_rate` (renames per second)
5. $x_5$: `suspicious_ext_rate` (renames to `.locked`, `.crypto`, etc.)
6. $x_6$: `cpu_percent` (process CPU utilization)
7. $x_7$: `children_spawned` (subprocess fan-out)
8. $x_8$: `io_bytes_per_s` (storage throughput)
9. $x_9$: `touched_file_count` (distinct files accessed)

### 4.3 Ensemble Scoring Function
$$\text{RiskScore} = \min\left(1.0, w_{\text{rule}} \cdot S_{\text{rule}}(\vec{x}) + w_{\text{ml}} \cdot S_{\text{ml}}(\vec{x})\right)$$
- When $\text{RiskScore} \ge 0.60 \rightarrow$ High Alert emitted to SOC.
- When $\text{RiskScore} \ge 0.80 \rightarrow$ Automated Active Containment Triggered.

---

## 5. Subsystem Directory & Component Index

If you need to investigate or explain any part of the project, refer to this directory map:

| Subsystem | Primary Files | What It Does |
| :--- | :--- | :--- |
| **Active Containment** | `backend/mitigation.py` | Recursive tree discovery, thread quantum freezing (`suspend`), `SIGTERM`/`SIGKILL`. |
| **gRPC Telemetry** | `proto/edr_telemetry.proto`<br>`backend/grpc_server.py`<br>`agent/edr_agent.py` | Protocol Buffer definitions, binary streaming ingestion, and remote endpoint sensor client. |
| **Behavioral Core** | `core/engine.py`<br>`core/features.py`<br>`models/rf_classifier.pkl` | Sliding temporal window, 9-feature extraction, Shannon entropy calculation, Random Forest scoring. |
| **Proactive Hardening** | `core/canary.py`<br>`core/ioc_auditor.py` | Cryptographic bait files with SHA-256 checks and MITRE ATT&CK pre-encryption command auditing. |
| **Database Layer** | `backend/database.py`<br>`backend/models.py`<br>`backend/repository.py` | Async SQLAlchemy 2.0 engine, 6 relational schemas in `edr_storage.db`, background worker threads. |
| **Streaming Scanner** | `backend/scan_router.py` | 1MB chunked upload scanner with an $O(1)$ memory 256-bin histogram for Shannon entropy. |
| **WebSockets** | `backend/websocket_manager.py` | Multi-channel connection manager (`telemetry`, `alerts`, `mitigation`, `scans`, `system`). |
| **MLOps Pipeline** | `mlops/retrain_pipeline.py`<br>`backend/mlops_router.py` | Continuous model retraining, artifact versioning, and zero-downtime in-memory hot reloading. |
| **SOC Dashboard** | `ransomweb/src/routes/index.tsx`<br>`ransomweb/src/components/` | React 19 / TanStack Start dashboard with live risk dial, 5-stage tracker, report modals, and file scanner. |
| **Automated Tests** | `tests/` (6 test suites) | 37 unit and integration tests verifying all subsystems end-to-end. |

---

## 6. Resilience & Fault-Tolerance Mechanisms

1. **Memory Ceiling & $O(1)$ RAM Bounds**:
   - The file scanner (`scan_router.py`) limits uploads to 50MB (`HTTP 413`) and calculates Shannon entropy using an online 256-bin histogram array, consuming **only 256 integers of RAM** regardless of file size.
2. **Non-Blocking Database Transactions**:
   - Database operations are dispatched to a dedicated background `ThreadPoolExecutor` (`save_alert_background`, `save_scan_background`). High disk write bursts by malware never cause thread blocking in the detection loop.
3. **Graceful IPC Fail-Open**:
   - If an endpoint loses network connectivity to the central gRPC server, the local sensor (`agent/edr_agent.py`) buffers telemetry in a bounded memory queue and executes local mitigation independently if tripwires trigger.
4. **Zero-Downtime Model Promotion**:
   - Retrained models are serialized to versioned artifacts (`rf_classifier_v2.*.pkl`), atomically swapped with `models/rf_classifier.pkl`, and injected directly into active Python memory without dropping WebSocket connections or restarting services.
