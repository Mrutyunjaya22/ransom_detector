# Ransomweb Model Connection Guide

This document explains how the `ransomweb` frontend connects to the Python backend and how the ML model is used in the system.

## 1. Purpose

This file is focused on the request flow for `ransomweb`, the backend API integration, and the runtime location of the model.

## 2. System components

- `ransomweb/` — frontend UI built with TanStack Start, React, and Vite.
- `backend/` — Python FastAPI backend service that exposes REST endpoints.
- `core/` — runtime pipeline logic, collectors, engine, alerts, and forensics.
- `models/rf_classifier.pkl` — persisted RandomForest model used for inference.
- `backend/pipeline_service.py` — service that loads the model and orchestrates a detection run.

## 3. High-level architecture

The connection is layered into three main concerns:

- `Browser UI` — user-facing React pages, controls, and local route handlers in `ransomweb/`.
- `Frontend API layer` — wrappers in `ransomweb/src/lib/api.ts` and server proxies in `ransomweb/src/routes/api/*.ts`.
- `Backend API` — Python FastAPI application in `backend/app.py` that delegates work to `backend/pipeline_service.py`.

The actual ML model is never loaded in the browser. Instead, the browser sends HTTP requests to the backend API, and the backend loads and uses the model internally.

### Connection summary

- Browser UI calls `ransomweb/src/lib/api.ts` functions.
- `api.ts` uses `backend-proxy.ts` to build HTTP requests to the backend host.
- Nitro route handlers in `ransomweb/src/routes/api/*.ts` can also proxy requests directly from the server side.
- The backend receives requests in `backend/app.py`.
- `backend/app.py` forwards work to `pipeline_service.pipeline_service`.
- `pipeline_service.py` loads `models/rf_classifier.pkl`, creates runtime components, and executes the detection pipeline.

## 4. Backend API details

### `backend/app.py`

This file defines the API surface. The backend exposes:

- `GET /api/status`
- `GET /api/alerts`
- `GET /api/reports`
- `GET /api/reports/{report_id}`
- `POST /api/run`

`app.py` passes these calls to `pipeline_service.pipeline_service`.

### `backend/pipeline_service.py`

This file contains the runtime logic for the detection pipeline.

Important behavior:

- Model file path is `models/rf_classifier.pkl`
- `PipelineService.start_run(mode)` does:
  - `self._engine = BehavioralEngine(MODEL_PATH)`
  - `self._alert_manager = AlertManager(...)`
  - `self._collector = Collector(...)`
  - spawn `simulate_activity.py`
  - run the pipeline loop, ingest events, compute risk, and generate reports

The model is loaded only on the backend inside `BehavioralEngine`.

## 5. Frontend integration

### `ransomweb/src/lib/backend-proxy.ts`

This helper constructs backend API calls using:

```ts
const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
```

It provides:
- `backendGet(path)`
- `backendPost(path, body)`

### `ransomweb/src/lib/api.ts`

This wrapper maps UI actions to backend endpoints:

- `fetchStatus()` → `/api/status`
- `fetchAlerts()` → `/api/alerts`
- `fetchReports()` → `/api/reports`
- `fetchReport(id)` → `/api/reports/${id}`
- `startRun(mode)` → `/api/run`
- `fetchScans()` → `/api/scan`
- `analyzeWithModel(...)` → `/api/analyze`
- `scanFile(file)` → `/api/scan` (form upload)

These functions are used by React components and feature pages.

### `ransomweb/src/routes/api/*.ts`

These route modules proxy frontend server routes to the backend API. They run on the Nitro server side and forward local UI requests to the backend URL.

Examples:
- `src/routes/api/status.ts`
- `src/routes/api/alerts.ts`
- `src/routes/api/reports.ts`
- `src/routes/api/reports.$id.ts`
- `src/routes/api/run.ts`
- `src/routes/api/scan.ts`
- `src/routes/api/analyze.ts`

How the proxy works:
- The browser requests `/api/status`, `/api/run`, `/api/reports`, etc. from the frontend app.
- Nitro server handlers in `src/routes/api/*.ts` intercept those calls.
- Each handler uses `fetch(`${BACKEND_URL}/api/...`)` to send the request to the backend.
- The backend response is returned as a local response to the browser.

This layer ensures the frontend can call backend APIs without embedding the backend host in every component.

### Route proxy details

Each file under `ransomweb/src/routes/api/` implements a local proxy route using Nitro. The browser calls a local path such as `/api/status`, and Nitro forwards it to the backend host:

- `status.ts` forwards GET `/api/status`
- `alerts.ts` forwards GET `/api/alerts`
- `reports.ts` forwards GET `/api/reports`
- `reports.$id.ts` forwards GET `/api/reports/${id}`
- `run.ts` forwards POST `/api/run`
- `scan.ts` forwards GET and POST `/api/scan`
- `analyze.ts` forwards POST `/api/analyze`

The proxy handlers perform request validation and then `fetch(`${BACKEND_URL}/api/...`)`. The response body and status code are returned unchanged.

## 6. Detailed request flows

### Start run flow

1. User clicks the run button in the UI.
2. The frontend component calls `startRun(mode)` in `ransomweb/src/lib/api.ts`.
3. `startRun()` uses `backendPost("/api/run", { mode })`.
4. `backendPost()` in `ransomweb/src/lib/backend-proxy.ts` sends an HTTP POST to:
   - `http://127.0.0.1:8000/api/run`
   - or `VITE_API_BASE_URL + /api/run` if configured
5. FastAPI `backend/app.py` receives `/api/run`.
6. `app.py` calls `pipeline_service.start_run(mode)`.
7. `PipelineService.start_run()` does:
   - load the ML model from `models/rf_classifier.pkl`
   - create `BehavioralEngine(MODEL_PATH)`
   - start the `Collector`
   - spawn `simulate_activity.py`
   - begin the pipeline loop to ingest events, score them, generate alerts/reports
8. The backend returns a run status payload to the frontend.
9. The UI can then poll:
   - `/api/status`
   - `/api/alerts`
   - `/api/reports`
   to show current stage, alerts, and generated reports.

#### Run request and response payloads

- Request: `POST /api/run`
  - Body: `{ "mode": "benign" | "attack" }`
- Successful response:
  - `{ "mode": string, "stage": string, "process": { "name": string, "pid": number }, "durationSec": number }`
- Error conditions:
  - `400` if `mode` is invalid
  - `409` if a run is already in progress

#### Status response payload

- Request: `GET /api/status`
- Response:
  - `pipeline.healthy` boolean
  - `pipeline.stage` string
  - `pipeline.mode` string
  - `pipeline.uptimeSec` number
  - `pipeline.eventsProcessed` number
  - `modelLoaded` boolean
  - `collectorActive` boolean
  - `monitoredProcess` object with `name` and `pid`
  - `riskScore` number
  - `threshold` number
  - `alertCount` number

---

### Scan file flow

1. User selects or drops a file in the file scanner component.
2. The UI calls `scanFile(file)` in `ransomweb/src/lib/api.ts`.
3. `scanFile()` builds `FormData` and POSTs to:
   - `http://127.0.0.1:8000/api/scan`
4. The backend is expected to receive `/api/scan` and process the uploaded file.
   - in a complete integration, this would invoke the model or scanner logic
   - the frontend then receives a `ScanResultItem` response
5. The UI displays the scan verdict, score, reasons, and feature values.

> Note: In the current backend implementation, `backend/app.py` does not define `/api/scan` or `/api/analyze`.
> That means the UI and Nitro route proxy can build and send these requests, but the backend will return a 404 unless those endpoints are implemented.

### Backend runtime execution path

When `POST /api/run` is received, the backend sequence is:

1. `pipeline_service.start_run(mode)` acquires a lock and validates the current state.
2. `BehavioralEngine(MODEL_PATH)` loads `models/rf_classifier.pkl`.
3. `AlertManager` is created with the configured threshold.
4. `Collector` is created to monitor `test_sandbox` activity.
5. A subprocess is launched to execute `simulate_activity.py`, which generates test events.
6. A daemon thread runs `_run_loop()`, polling the collector queue, ingesting events, and updating pipeline state.
7. For each queued event:
   - `self._engine.ingest(event)` processes the event
   - `self.events_processed` increments
   - `self._engine.risk_score(pid)` computes the current risk score for the monitored PID
   - `AlertManager.evaluate(...)` decides whether an alert should be created
8. If an alert occurs, it is formatted and appended to `self.alerts`.
9. When the subprocess exits and the collector queue drains, the backend may generate a JSON report file using `generate_incident_report(...)`.

This runtime path is where the persisted `rf_classifier.pkl` model is actively used.

---

### High-level model connection

- `models/rf_classifier.pkl` is the persisted ML model
- `backend/pipeline_service.py` loads and uses the model
- `backend/app.py` exposes the API endpoints
- `ransomweb/src/lib/backend-proxy.ts` forwards frontend calls to backend
- `ransomweb/src/lib/api.ts` maps UI actions to backend endpoints

## 7. Where the model lives

The model lives in:

- `models/rf_classifier.pkl` — trained RandomForest model
- `backend/pipeline_service.py` — loads and uses the model at runtime
- `backend/app.py` — exposes the API endpoints the frontend calls
- `ransomweb/src/lib/backend-proxy.ts` — sends frontend requests to the backend
- `ransomweb/src/lib/api.ts` — maps UI actions to backend endpoints

## 8. Missing backend endpoints

The frontend currently includes calls for additional functionality that are not yet implemented in the backend.

- `ransomweb/src/lib/api.ts` includes `fetchScans()` and `scanFile(file)` for `/api/scan`.
- `ransomweb/src/lib/api.ts` includes `analyzeWithModel(...)` for `/api/analyze`.
- `ransomweb/src/routes/api/scan.ts` and `ransomweb/src/routes/api/analyze.ts` proxy these paths to the backend.
- `backend/app.py` only implements `/api/status`, `/api/alerts`, `/api/reports`, `/api/reports/{report_id}`, and `/api/run`.

Therefore, the UI can send scan/analyze requests, but the backend must be extended before those features will work.

## 9. Summary

The structured connection is:

1. Frontend UI calls `ransomweb/src/lib/api.ts`
2. `api.ts` calls `ransomweb/src/lib/backend-proxy.ts`
3. `backend-proxy.ts` sends requests to FastAPI in `backend/app.py`
4. `app.py` delegates to `backend/pipeline_service.py`
5. `pipeline_service.py` loads `models/rf_classifier.pkl` and runs detection

This file is intended as a reference for how the model and frontend are connected in the repository.
