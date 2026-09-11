# Enterprise EDR Platform — Detailed Setup & Architecture Guide

This guide provides technical specifications, complete local and distributed installation steps, architectural tier breakdowns, and API contracts for the **AI-Powered Behavioral Ransomware Detection & SOC Triage Platform (EDR)**.

---

## 1. Multi-Tier Distributed Architecture

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           1. ENDPOINT SENSOR TIER                       │
│  [ agent/edr_agent.py ]                                                 │
│  ├── Filesystem Watcher (watchdog)   ──> FileEvent Stream               │
│  ├── Process Telemetry (psutil)      ──> ProcessMetric Stream           │
│  ├── Canary Decoy Traps (core/canary.py)                                │
│  └── Pre-Encryption IoC Auditor (core/ioc_auditor.py)                   │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ gRPC / HTTP/2 (Port 50051)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      2. INGESTION & CENTRAL SERVER TIER                 │
│  [ backend/grpc_server.py ] ──> Ingests TelemetryBatch                  │
│  [ backend/app.py ]         ──> FastAPI REST Gateway (Port 8000)        │
│  [ backend/websocket_manager.py ] ──> Multiplexed WebSocket Broadcaster │
│  [ backend/scan_router.py ] ──> 1MB Chunked Streaming File Triage       │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      3. DETECTION & ACTIVE CONTAINMENT                  │
│  [ core/engine.py ]                                                     │
│  ├── Sliding Window (10s Ring Buffer)                                   │
│  ├── Heuristic Rule Engine (Entropy Spikes, Mass Rename, Write Rate)    │
│  └── ML Scorer (RandomForestClassifier, 9 Behavioral Features)          │
│  [ backend/mitigation.py ]                                              │
│  └── ProcessMitigator (Thread Quantum Freeze + Tree SIGTERM/SIGKILL)     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                  ┌──────────────────┴──────────────────┐
                  ▼                                     ▼
┌───────────────────────────────────┐ ┌───────────────────────────────────┐
│   4. ASYNC PERSISTENCE TIER       │ │     5. SOC TRIAGE & MLOPS         │
│  [ backend/database.py & repo.py ]│ │  [ ransomweb/ ]                   │
│  ├── SQLite (aiosqlite) / Postgres│ │  ├── React 19 / TanStack Start    │
│  ├── Agents & Heartbeats          │ │  ├── Real-time Alerts & Gauges    │
│  ├── Security Alerts              │ │  ├── Incident Timeline & Export   │
│  ├── Forensic Reports             │ │  └── File Artifact Scanner        │
│  └── Scans & Feedback Records     │ │  [ mlops/retrain_pipeline.py ]    │
└───────────────────────────────────┘ └───────────────────────────────────┘
```

---

## 2. Complete Environment Setup Guide

### 2.1 Prerequisites
- **Python**: Version 3.12+ (64-bit)
- **Node.js**: Version 20+ (with npm)
- **Git**: For source control management
- **Operating System**: Windows 10/11 or Linux (Ubuntu 22.04+)

---

### 2.2 Backend Environment Setup (Python)

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/Mrutyunjaya22/ransom_detector.git
   cd ransom_detector
   ```

2. **Create and activate virtual environment**:
   - **Windows PowerShell**:
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS**:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install Python dependencies**:
   ```powershell
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```
   *Installed dependencies include: `fastapi`, `uvicorn`, `sqlalchemy>=2.0.0`, `aiosqlite`, `grpcio>=1.60.0`, `grpcio-tools>=1.60.0`, `protobuf>=4.25.0`, `watchdog`, `psutil`, `scikit-learn`, `numpy`, and `python-multipart`.*

4. **Compile Protocol Buffer Stubs** (If modifying `.proto`):
   ```powershell
   python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/edr_telemetry.proto
   ```

5. **Initialize Database & Model Baseline**:
   - The database (`edr_storage.db`) initializes automatically when the backend boots.
   - The Random Forest baseline model is pre-compiled at `models/rf_classifier.pkl`. To re-train from scratch:
     ```powershell
     python train_model.py
     ```

---

### 2.3 Frontend Environment Setup (React 19 / TanStack Start)

1. **Navigate to the frontend directory**:
   ```powershell
   cd ransomweb
   ```

2. **Install frontend dependencies**:
   ```powershell
   npm install
   ```

3. **Configure environment variables (Optional)**:
   Create `ransomweb/.env` if you need custom API URLs:
   ```env
   VITE_API_BASE_URL=http://127.0.0.1:8000
   ```

4. **Verify frontend production build**:
   ```powershell
   npm run build
   ```
   *Should build cleanly in $<2$ seconds without TypeScript or Nitro errors.*

---

## 3. Running the Complete Platform

To run the entire distributed system, open **4 terminal windows**:

### Terminal 1: Central REST & WebSocket Server
```powershell
# From project root
.\.venv\Scripts\python.exe backend/app.py
```
*Listens on `http://127.0.0.1:8000` with automatic hot-reloading.*

### Terminal 2: gRPC Telemetry Ingestion Server
```powershell
# From project root
.\.venv\Scripts\python.exe backend/grpc_server.py
```
*Listens on `127.0.0.1:50051` for binary endpoint telemetry.*

### Terminal 3: Standalone Remote Endpoint Sensor Agent
```powershell
# From project root (or deployed to any remote endpoint)
.\.venv\Scripts\python.exe agent/edr_agent.py --server 127.0.0.1:50051 --watch ./test_sandbox
```
*Monitors filesystem and process activity, streaming batches to the central server.*

### Terminal 4: SOC Web Dashboard
```powershell
cd ransomweb
npm run dev
```
*Access the SOC dashboard in your browser at `http://localhost:3000`.*

---

## 4. API & Protocol Contracts Reference

### 4.1 FastAPI REST Endpoints

| Method | Route | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Current pipeline health, active stage, risk score, monitored process |
| `GET` | `/api/alerts` | Paginated security alerts loaded from relational database with in-memory fallback |
| `GET` | `/api/reports` | Incident reconstruction reports index |
| `GET` | `/api/reports/{id}` | Detailed forensic report with chronological timeline, features, and alerts |
| `POST` | `/api/run` | Triggers a simulated workload (`{"mode": "benign"}` or `{"mode": "attack"}`) |
| `POST` | `/api/scan` | Chunked 1MB streaming file upload ($O(1)$ memory Shannon entropy, 50MB ceiling) |
| `GET` | `/api/scans` | Historical artifact triage scans |
| `POST` | `/api/agents/register` | Registers remote endpoint sensors and records heartbeat |
| `POST` | `/api/ml/feedback` | Ingests analyst ground truth (`true_positive` / `false_positive`) |
| `GET` | `/api/ml/model/latest` | Returns active model metadata (version, accuracy, F1, precision, recall) |
| `GET` | `/api/ml/model/download` | Binary download of production `rf_classifier.pkl` artifact |
| `POST` | `/api/ml/retrain` | Triggers continuous retraining loop and hot-reloads weights into memory |

---

### 4.2 WebSocket Broadcaster Channels (`/ws/soc`)

The WebSocket connection manager exposes 5 dedicated multiplexed channels:
1. `telemetry`: Streaming evaluations of process behavioral vectors.
2. `alerts`: Instant threat alerts when risk crosses $\ge 0.60$.
3. `mitigation`: Real-time killswitch telemetry (PIDs terminated, execution time in ms).
4. `scans`: Live artifact triage completions.
5. `system`: Model promotion notifications and keep-alive heartbeats.

---

### 4.3 gRPC Service Definition (`proto/edr_telemetry.proto`)

```protobuf
service EDRTelemetryService {
  rpc RegisterAgent (AgentInfo) returns (RegistrationResponse);
  rpc StreamTelemetry (stream TelemetryBatch) returns (stream MitigationDirective);
  rpc SendHeartbeat (Heartbeat) returns (HeartbeatAck);
}
```

---

## 5. Automated Verification & Testing

The platform includes **37 automated unit and integration tests** across 6 comprehensive suites:

```powershell
.\.venv\Scripts\python.exe -m unittest discover tests -v
```

### Test Suite Inventory:
1. **`tests/test_api_endpoints.py`** (7 tests): Validates REST schema, status payloads, alert formatting, report transformations, and streaming scanner uploads.
2. **`tests/test_phase1_hardening.py`** (5 tests): Validates `ProcessMitigator` thread suspension and process tree termination, magic byte recognition, and WebSocket sync broadcasting.
3. **`tests/test_persistence.py`** (6 tests): Validates async SQLAlchemy tables, agent registration, alert persistence, report retrieval, and analyst feedback records.
4. **`tests/test_grpc_agent.py`** (3 tests): Validates gRPC server startup, agent registration, heartbeat validation, and bidirectional streaming with threat mitigation directives.
5. **`tests/test_phase4_threats.py`** (9 tests): Validates `CanaryTrapManager` decoy deployment and SHA-256 integrity verification, tamper detection, and pre-encryption IoC auditing (`vssadmin`, `bcdedit`, `wbadmin`, `wevtutil`, `net stop`).
6. **`tests/test_mlops_pipeline.py`** (6 tests): Validates analyst feedback ingestion, model metadata retrieval, artifact download, and live retraining with in-memory hot-reloading.
