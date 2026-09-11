# Ransomware Detection & SOC Triage Dashboard (Frontend)

The frontend web interface for the **AI-Powered Behavioral Ransomware Detection & SOC Triage Platform (EDR)**. Built with **React 19**, **TanStack Start**, **Vite**, and **Tailwind CSS**, this dashboard provides security analysts with sub-second visibility and active triage capabilities during live ransomware detonations.

---

## 1. Key Features & Visual Components

- **Real-Time Pipeline Status**: Live status indicator displaying system health, model load state, active collector, and monitored process ID.
- **5-Stage Detection Lifecycle**: Visual progression tracker across `Collecting` $\rightarrow$ `Feature Extraction` $\rightarrow$ `Scoring` $\rightarrow$ `Correlating` $\rightarrow$ `Reporting`.
- **Interactive Risk Dial Gauge**: Real-time visualization of combined risk scores ($0.00$ to $1.00$) calculated from heuristic rules and Random Forest ML.
- **Live Evidence Feed**: Granular behavioral anomaly log showing file operation velocity, Shannon entropy spikes, and suspicious rename patterns.
- **Forensic Incident Reports**:
  - Filterable table of past detected incidents.
  - Detailed modal inspection featuring chronological event timelines and behavioral feature breakdowns.
  - **Export JSON**: One-click export for incident report preservation and external SIEM ingestion.
- **Streaming File Artifact Scanner**:
  - Drag-and-drop file upload evaluated in 1MB chunks with $O(1)$ memory Shannon entropy calculation.
  - AI-assisted threat triage identifying MITRE ATT&CK techniques, likely malware families, and response playbooks (with local heuristic analyst fallback when cloud LLMs are unavailable).
- **Simulation Control Panel**: Buttons to trigger `Run Benign` and `Run Attack` simulation workloads directly from the UI.

---

## 2. Technology Stack

- **Framework**: [TanStack Start](https://tanstack.com/start) (Full-stack SSR / Vite framework)
- **UI Library**: React 19
- **Styling**: Tailwind CSS & Class Variance Authority (CVA)
- **Component Primitives**: Radix UI (Dialog, Progress, Badge, Tooltips)
- **Icons**: Lucide React
- **State & Data Fetching**: TanStack React Query v5
- **Server Engine**: Nitro server with file-based routing in `src/routes/`

---

## 3. Local Development & Build

### Prerequisites
- Node.js 20+ (with npm)
- Central backend server running on `http://127.0.0.1:8000`

### Installation
```bash
cd ransomweb
npm install
```

### Start Development Server
```bash
npm run dev
```
Open `http://localhost:3000` in your browser.

### Production Build
```bash
npm run build
```
Generates an optimized client and server-side production bundle in `.output/`.
Verified to compile with zero TypeScript or Nitro bundle errors.

---

## 4. API Proxy Integration

Frontend requests to `/api/...` are proxied to the FastAPI backend through Nitro route handlers in `src/routes/api/`:
- `src/routes/api/status.ts` $\rightarrow$ `GET http://127.0.0.1:8000/api/status`
- `src/routes/api/alerts.ts` $\rightarrow$ `GET http://127.0.0.1:8000/api/alerts`
- `src/routes/api/reports.ts` $\rightarrow$ `GET http://127.0.0.1:8000/api/reports`
- `src/routes/api/run.ts` $\rightarrow$ `POST http://127.0.0.1:8000/api/run`
- `src/routes/api/scan.ts` $\rightarrow$ `POST / GET http://127.0.0.1:8000/api/scan`
- `src/routes/api/analyze.ts` $\rightarrow$ AI-assisted threat triage with built-in heuristic fallback.
