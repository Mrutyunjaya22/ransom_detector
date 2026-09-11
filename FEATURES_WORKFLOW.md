# Ransomware Detection Prototype — Feature Workflow

This document explains how all major features work together in the ransomware detection prototype, from the browser UI to the model and forensic reconstruction.

## 1. Architecture overview

The prototype is split into three main layers:

- **Frontend** (`ransomweb/`): React UI built with TanStack Start, Vite, and TypeScript.
- **Backend** (`backend/`): FastAPI service exposing pipeline and report endpoints.
- **Core pipeline** (`core/`): Collector, feature extraction, behavioral engine, alerting, and forensic report generation.

The model file used for inference is stored in `models/rf_classifier.pkl`.

## 2. Feature map

### 2.1 Live pipeline monitor

The dashboard shows:

- Pipeline health and active stage
- Model load status
- Collector status
- Workload mode (`idle`, `benign`, `attack`)
- Live risk score and threshold view
- Active alerts list
- Evidence feed of behavioral signals
- Recent forensic reports

This view is powered by the backend API response from `GET /api/status`, `GET /api/alerts`, and `GET /api/reports`.

### 2.2 Multi-stage behavioral analysis

The detection pipeline is surfaced as distinct stages:

1. `collecting`
   - The collector watches sandbox filesystem events and polls process telemetry.
   - It buffers events for analysis.
2. `feature-extraction`
   - Raw events become numeric signals such as entropy, file operation rate, extension changes, CPU%, and IO.
3. `scoring`
   - A rule-based layer and the ML model both score the behavior.
   - Their outputs are combined into a single risk score.
4. `correlating`
   - Suspicious signals are correlated across files and processes.
   - This stage decides whether the behavior is coherent enough to raise an alert.
5. `reporting`
   - Forensic reconstruction produces an incident report with timeline data, alerts, and recommended actions.

### 2.3 File scanner and model triage

The UI includes a file scanner component that accepts file uploads.

- The file is sent to the backend via `POST /api/scan`.
- A scan result is returned containing verdict, score, reasons, and extracted features.
- This enables quick model-based triage of suspicious files.

> Note: The backend implements `/api/scan` with real-time Shannon entropy extraction, file header analysis, ransomware extension checking, and ML model evaluation.

### 2.4 Forensic reporting

After a run completes, the backend can write incident reports into `reports/`.

A report contains:

- Incident ID
- Mode (`benign` or `attack`)
- Verdict
- Peak risk score
- Alert count
- Generated timestamp
- Process ID
- Timeline of suspicious events
- Features and signals supporting the detection
- Recommendations for response

The UI can load detail pages for each report via `GET /api/reports/{report_id}`.

## 3. Backend feature details

### 3.1 FastAPI endpoints

The backend exposes these endpoints:

- `GET /api/status`
  - returns pipeline state, model status, risk score, thresholds, and analysis summary.
- `GET /api/alerts`
  - returns the latest active alerts.
- `GET /api/reports`
  - returns the report index.
- `GET /api/reports/{report_id}`
  - returns a single forensic report.
- `POST /api/run`
  - starts a detection run in `benign` or `attack` mode.

### 3.2 Pipeline orchestration

`backend/pipeline_service.py` manages runtime state.

- `PipelineService.start_run(mode)`:
  - loads the ML model from `models/rf_classifier.pkl`
  - creates `BehavioralEngine`
  - starts `Collector`
  - launches `simulate_activity.py` to generate sandbox events
  - starts a background loop to ingest and score events

- `_run_loop()`:
  - reads events from the collector queue
  - ingests them into the engine
  - updates live risk score
  - evaluates alerts
  - generates a forensic report after the workload finishes

### 3.3 Live analysis payload

The backend enriches the status response with:

- `analysis.currentStage`
- `analysis.activeStages`
- `analysis.evidence`
- `analysis.summary`

This supports the dashboard’s multi-stage explanation and evidence feed.

## 4. Core pipeline features

### 4.1 Collector

The collector combines two telemetry sources:

- Filesystem watcher (`watchdog`)
  - tracks create, modify, rename, delete events
- Process monitor (`psutil`)
  - samples CPU, IO, and child process count

Each event becomes a typed `Event` object with a timestamp, kind, PID, path, and extra metadata.

### 4.2 Feature extraction

`core/features.py` converts raw events into numeric signals:

- `shannon_entropy()` calculates file entropy
- `safe_read_entropy()` reads file bytes and returns entropy or `None`
- `ExtensionTracker` tracks extension changes and suspicious rename rates
- `LatestEntropyTracker` keeps the most recent entropy sample for each touched file

### 4.3 Behavioral engine

`core/engine.py` manages the sliding window and scoring:

- `SlidingWindow` holds recent events per PID
- `RuleEngine` scores obvious ransomware signals
- `MLScorer` loads `rf_classifier.pkl` and returns a probability score
- `BehavioralEngine.risk_score(pid)` returns:
  - rule score
  - ML score
  - combined risk score
  - reasons and features

### 4.4 Alerting

`core/alert.py` evaluates the risk result and raises alerts when thresholds are exceeded.

Alerts include:

- timestamp
- PID
- risk, rule, ML scores
- affected file paths
- suspicious reasons
- recommended action

### 4.5 Forensics

`core/forensics.py` builds incident reports from buffered events.

Reports capture:

- event timelines
- entropy trends
- suspicious behaviors
- alert trigger reasons

## 5. Frontend feature details

### 5.1 API wrapper

`ransomweb/src/lib/api.ts` provides typed functions for the UI:

- `fetchStatus()`
- `fetchAlerts()`
- `fetchReports()`
- `fetchReport(id)`
- `startRun(mode)`
- `fetchScans()`
- `analyzeWithModel(input)`
- `scanFile(file)`

### 5.2 Request proxy layer

The frontend proxies requests through Nitro route handlers in `ransomweb/src/routes/api/`.

This means browser calls to `/api/...` are forwarded to the backend host under the hood, while preserving a simple local API shape for the UI.

### 5.3 Dashboard behavior

The main dashboard page:

- polls `/api/status`, `/api/alerts`, and `/api/reports`
- renders live risk score, stages, and alerts
- shows a multi-stage evidence feed
- lets users start benign or attack simulation runs
- displays recent forensic reports and a report detail dialog

### 5.4 Explanation panel

A dedicated “How it works” panel describes:

- what each stage does
- why the score changes
- how behavior is correlated and reported

## 6. How the model is used

- The ML model file is `models/rf_classifier.pkl`.
- It is loaded only by the backend in `core/engine.py` via `MLScorer`.
- The browser never directly loads or uses the model.
- During runtime, the model evaluates the latest extracted features and contributes an `ml_score` to the combined risk.

## 7. End-to-end flow summary

### Starting a run

1. UI button clicks `startRun("benign")` or `startRun("attack")`.
2. Frontend sends `POST /api/run`.
3. Backend loads the model and starts the collector.
4. `simulate_activity.py` produces sandbox events.
5. The collector ingests events and the engine computes risk.
6. Alerts are raised if the combined score crosses threshold.
7. A forensic report is generated after the workload finishes.

### Monitoring live behavior

1. UI polls `GET /api/status` repeatedly.
2. Status responses include live risk, stage, event count, and analysis evidence.
3. The dashboard updates the stage progression and evidence feed.

### Reviewing a report

1. User clicks a report entry.
2. UI requests `GET /api/reports/{report_id}`.
3. Detailed report data is displayed, including timeline, features, alerts, and recommendations.

## 8. Notes and next steps

- The prototype is designed for demo and investigation, not production use.
- In production, the collector should use OS-native telemetry (ETW, eBPF, auditd) instead of filesystem polling.
- The model should be retrained on real endpoint telemetry for deployable accuracy.
- Adding `POST /api/scan` and `POST /api/analyze` on the backend would complete the file-scanning/triage integration.
