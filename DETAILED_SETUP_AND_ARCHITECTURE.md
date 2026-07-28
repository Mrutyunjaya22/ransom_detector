# Ransomware Detection Prototype — Setup & Architecture Guide

This document describes how to set up the project, run the backend and frontend, and explains how the model and pipeline work together.

## 1. Project structure

Root repository layout:

- `backend/` — FastAPI backend service exposing runtime status, alerts, reports, and run control.
- `core/` — detection pipeline implementation and runtime inference logic.
- `models/` — trained model persistence (`rf_classifier.pkl`).
- `reports/` — generated incident reports.
- `ransomweb/` — frontend dashboard built with TanStack Start, React, TypeScript, and Vite.
- `simulate_activity.py` — synthetic workload generator used by the backend pipeline.
- `train_model.py` — the training script that generates the RandomForest model.
- `main.py` — end-to-end pipeline orchestrator/test runner.

## 2. Setup guide

### 2.1 Python backend setup

1. Create and activate a Python virtual environment.

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install Python requirements.

```bash
pip install -r requirements.txt
```

3. Train the model.

```bash
python train_model.py
```

This generates `models/rf_classifier.pkl`.

4. Start the backend API.

```bash
python backend/app.py
```

The backend listens by default on `http://127.0.0.1:8000`.

### 2.2 Frontend setup

1. Change into the frontend directory.

```bash
cd ransomweb
```

2. Install frontend dependencies.

```bash
npm install
```

3. Start the development app.

```bash
npm run dev
```

4. Open the browser URL shown by Vite.

The frontend uses the backend URL `http://127.0.0.1:8000` by default.

### 2.3 Build the frontend for production

From `ransomweb`:

```bash
npm run build
```

The build has been verified and completes successfully.

## 3. Backend API overview

The FastAPI backend is defined in `backend/app.py` and exposes these endpoints:

- `GET /api/status`
- `GET /api/alerts`
- `GET /api/reports`
- `GET /api/reports/{report_id}`
- `POST /api/run`

The user interface and route layer call these endpoints to read pipeline state and trigger runs.

### 3.1 Backend runtime and model loading

- `backend/app.py` delegates logic to `pipeline_service.pipeline_service`.
- `pipeline_service.py` loads the model from `models/rf_classifier.pkl` when a run starts.
- `PipelineService.start_run(mode)` creates the detection engine and starts a simulated workload.

## 4. Pipeline architecture

The repository implements a prototype five-stage behavioral ransomware detection pipeline.

### 4.1 Data collection

- `core/collector.py` collects filesystem and process events.
- It watches the sandbox directory and polls metrics for the monitored process.
- Events include file creation, modification, rename, delete, and process I/O/CPU changes.

### 4.2 Feature extraction

- `core/features.py` converts raw events into numeric features.
- It computes Shannon entropy, file operation rates, rename patterns, and extension changes.
- Example features:
  - `high_entropy_fraction`
  - `file_write_rate`
  - `extension_change_rate`
  - `mean_entropy`
  - `touched_file_count`

### 4.3 Behavioral analysis engine

- `core/engine.py` maintains a sliding window of recent events per PID.
- It computes two complementary scores:
  - a rule-based score for obvious ransomware indicators
  - an ML-based score from the trained RandomForest model
- Both scores are combined into a final `risk_score`.

### 4.4 Alerting

- `core/alert.py` raises an `Alert` when the combined risk score crosses a threshold.
- Alerts contain:
  - timestamp
  - PID
  - risk score
  - rule score
  - ML score
  - suspicious reasons
  - affected file paths

### 4.5 Forensics

- `core/forensics.py` builds a JSON incident report from buffered events.
- It records event timelines, entropy trends, and suspicious actions.
- Generated reports are stored under `reports/`.

## 5. Model training and inference

### 5.1 Training

- `train_model.py` produces synthetic training data representing benign and malicious behavior.
- It trains `sklearn.ensemble.RandomForestClassifier` with the same feature set used at runtime.
- The resulting model is saved to `models/rf_classifier.pkl`.

### 5.2 Inference

- At runtime, `core/engine.py` loads the trained model.
- The same feature set is computed from live events and passed into the model.
- The model output becomes the `ml_score` component of the final risk score.

## 6. Frontend integration

### 6.1 Frontend API wrapper

- `ransomweb/src/lib/backend-proxy.ts` contains `backendGet()` and `backendPost()`.
- These functions build requests using `VITE_API_BASE_URL` or the default backend URL.

### 6.2 UI backend mapping

- `ransomweb/src/lib/api.ts` exposes typed helper functions:
  - `fetchStatus()`
  - `fetchAlerts()`
  - `fetchReports()`
  - `fetchReport(id)`
  - `startRun(mode)`
  - `fetchScans()`
  - `analyzeWithModel(input)`
  - `scanFile(file)`

### 6.3 Route proxy layer

- `ransomweb/src/routes/api/*.ts` proxy UI server routes to backend endpoints.
- This layer forwards /api requests from the frontend to the Python backend.

### 6.4 Single action request flow

#### Start run
1. Browser UI invokes `startRun(mode)`.
2. `startRun()` sends POST `/api/run` to backend.
3. FastAPI calls `pipeline_service.start_run(mode)`.
4. Pipeline loads the model and starts the simulated workload.
5. The UI polls `/api/status`, `/api/alerts`, and `/api/reports` to display progress.

#### Scan file
1. User selects a file in the scanner UI.
2. `scanFile(file)` posts multipart form data to `/api/scan`.
3. Backend receives the file and performs scan logic.
4. The UI displays scan results including verdict, score, and reasons.

## 7. How this prototype performs

### 7.1 Detection goals

The pipeline is designed to detect ransomware-like behavior using both heuristics and machine learning.

### 7.2 What the model learns

The RandomForest model learns patterns such as:
- very high file entropy produced by encryption
- rapid file writes or creations
- mass rename operations with suspicious extensions
- high file operation density from a single process

### 7.3 What the rule layer detects

The rule layer catches clear ransomware behaviors such as:
- many files being renamed quickly
- extension changes that look like encryption output
- high entropy across several files
- sudden process activity spikes

### 7.4 Combined scoring

At runtime, the pipeline produces:
- `rule_score` from deterministic heuristics
- `ml_score` from the trained model
- `risk_score` that combines both

If the final risk score exceeds the configured threshold, an alert is generated.

### 7.5 Practical output

The backend returns operational status and alerts fast enough for dashboard updates.
The generated forensic report is also saved for later investigation.

## 8. Important notes

- `simulate_activity.py` is a synthetic workload generator; it is not real ransomware.
- The prototype is a proof-of-concept, not a production EDR system.
- In production, the collector should be replaced by OS-level telemetry hooks rather than filesystem polling.
- The ML model should be trained on real labeled endpoint data for real-world deployment.

## 9. Recommended commands

```bash
# Train and run backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python train_model.py
python backend/app.py

# Frontend
cd ransomweb
npm install
npm run dev
```

## 10. Additional references

- `core/collector.py` — data collection logic
- `core/features.py` — feature extraction used by both training and inference
- `core/engine.py` — behavioral scoring and model inference
- `core/alert.py` — alert generation
- `core/forensics.py` — report generation
- `backend/app.py` — API surface
- `backend/pipeline_service.py` — runtime orchestration and model loading
- `ransomweb/src/lib/api.ts` — frontend backend API wrapper
- `ransomweb/src/lib/backend-proxy.ts` — backend request helper
- `ransomweb/src/routes/api/*.ts` — frontend route proxies
