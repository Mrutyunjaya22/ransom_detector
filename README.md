# Behavioral Ransomware Detection Pipeline — Prototype

A working, end-to-end implementation of the 5-stage pipeline:

1. **Data collection** (`core/collector.py`) — filesystem watcher (watchdog) +
   process monitor (psutil, polled for CPU/IO/children). Includes a stub
   interface for where real crypto-API / ETW / eBPF hooks would plug in.
2. **Feature extraction** (`core/features.py`) — Shannon entropy, file-op rate,
   extension-change frequency, process-level features.
3. **Behavioral analysis engine** (`core/engine.py`) — 10s sliding window per
   process; rule layer for obvious spikes + `RandomForestClassifier` for
   subtler patterns; combined into one risk score.
4. **Detection & alerting** (`core/alert.py`) — threshold crossing fires an
   `Alert` with PID + affected paths (the actionable SOC/EDR output).
5. **Forensic reconstruction** (`core/forensics.py`) — replays the buffered
   event log for the flagged PID into a timeline + entropy trend, written as
   a JSON incident report (convertible to PDF).

## Quick start

1. Create and activate a Python environment.

```bash
# On Windows PowerShell:
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# On macOS/Linux:
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies.

```bash
pip install -r requirements.txt
```

3. Train the machine learning model.

```bash
python train_model.py
```

4. Run the detection pipeline.

```bash
python backend/app.py
```

`main.py` runs a benign workload first, then an attack-shaped workload, and writes incident reports to `reports/` if alerts fire.

## Run the frontend dashboard

1. Install frontend dependencies:

```bash
cd ransomweb
npm install
```

2. Start the frontend app:

```bash
npm run dev
```

3. Open the frontend in your browser at the URL shown by Vite.

The dashboard calls the Python backend at `http://127.0.0.1:8000` by default.

## Detailed system overview

### Pipeline summary
This repository implements a prototype ransomware detection pipeline with five stages:

- **Data collection** — `core/collector.py`
- **Feature extraction** — `core/features.py`
- **Behavioral analysis** — `core/engine.py`
- **Alerting** — `core/alert.py`
- **Forensics** — `core/forensics.py`

### 1. Data collection
The collector watches the sandbox directory and polls the monitored process:

- Filesystem events are captured by `watchdog`.
  - `fs_create` / `fs_modify` for new or updated files
  - `fs_rename` for file renames / extension changes
  - `fs_delete` for deleted files
- Process metrics are captured by `psutil`.
  - CPU percentage
  - child process count
  - IO bytes per second

All events are timestamped and placed into a thread-safe queue for the analysis engine.

### 2. Feature extraction
`core/features.py` converts raw events into numeric behavior features:

- `shannon_entropy` computes the entropy of a file’s bytes
- `safe_read_entropy` retries file reads and returns `None` when a file is unreadable
- `LatestEntropyTracker` stores the latest entropy per file path per PID
- `ExtensionTracker` records renames and suspicious extension patterns

Tracked features include:

- file operation rate
- mean entropy of touched files
- high-entropy file fraction
- extension-change rate
- suspicious rename rate
- count of touched files

### 3. Behavioral analysis engine
`core/engine.py` maintains a sliding window of recent events for each PID.

It uses two scoring layers:

- **Rule layer** (`RuleEngine`) detects obvious ransomware behaviors:
  - high-entropy fraction + mass writes
  - suspicious rename patterns like `.docx -> .locked`
  - rapid mass rename across many files
  - unusual child-process spawning
- **ML layer** (`MLScorer`) loads a trained `RandomForestClassifier` from `models/rf_classifier.pkl`.

The engine combines both scores into a single risk value and returns:

- `feature` values
- `rule_score`
- `ml_score`
- `risk_score`
- `reasons`

### 4. Alerting
`core/alert.py` checks the combined risk score against a threshold.

If the score is above the threshold and cooldown allows it, an `Alert` is created containing:

- timestamp
- PID
- risk score
- rule score
- ML score
- reasons
- affected paths

The alert is the actionable output that would feed a SOC dashboard or endpoint response.

### 5. Forensic reconstruction
`core/forensics.py` builds a human-readable incident report from buffered events:

- orders raw events by timestamp
- includes rename and file-touch details
- reconstructs entropy trend for touched files
- writes a JSON report into `reports/`

### Model training and inference
`train_model.py` generates synthetic training data and trains the RandomForest model.

- benign workload vectors represent normal user activity
- ransomware-like vectors represent high entropy, rapid writes, and mass renames
- the trained classifier is saved to `models/rf_classifier.pkl`

At runtime, `core/engine.py` loads this model and scores live behavior using the same feature set.

### Training purpose and output
The model is trained to distinguish between normal endpoint activity and ransomware-like behavior. Its purpose is not to encrypt files directly, but to provide a probabilistic score that helps the pipeline decide whether a monitored process should be investigated or alerted on.

During analysis, the system converts file and process events into numeric features, then passes those features into both:

- the rule engine for explainable heuristics
- the ML scorer for learned ransomware-like patterns

The combined output is a single `risk_score` plus supporting details:

- `rule_score` from explicit rules
- `ml_score` from the RandomForest model
- `reasons` explaining why the behavior is suspicious
- `affected_paths` for forensic context

The final result is used to trigger an `Alert` and to generate a forensic JSON incident report.

### Reference
This prototype is built on known ransomware indicators such as high file entropy, rapid file write/rename activity, and suspicious extension changes. See `train_model.py` for the training logic and `core/engine.py` for the inference and scoring logic.

### End-to-end workflow
When `main.py` runs:

1. `Collector` starts watching `test_sandbox/` and polling the target PID
2. `simulate_activity.py` runs either `benign` or `attack` workload
3. events flow into the `BehavioralEngine`
4. features are computed and scored every loop
5. alerts are fired when risk crosses the threshold
6. forensic reports are generated for alerted PIDs

### Why this prototype matters
This design shows how a ransomware detector can work from first file event to final alert:

- it captures file and process signals
- it measures entropy and rename behavior
- it uses rules plus ML for robust detection
- it preserves forensic evidence for post-incident analysis

### References
- Entropy-based ransomware detection is a common indicator used by security researchers for identifying encrypted or packed files.
- Mass rename and suspicious extension changes are described in ransomware behavior reports such as MITRE ATT&CK's "Data Encrypted for Impact" technique.
- Machine learning classification with a `RandomForestClassifier` is based on standard supervised learning practices; see scikit-learn documentation for model training and feature scoring.
- `watchdog` and `psutil` are the runtime sensor libraries used for filesystem and process instrumentation.
- This prototype is inspired by practical ransomware detection research that combines heuristic rules with behavioral ML scoring.

## Notes on the prototype vs. a production system

- `simulate_activity.py` is a **test fixture only** — it writes random bytes
  to its own throwaway files inside `test_sandbox/` to reproduce the
  *feature signature* (entropy jump, mass rename) the pipeline is built to
  catch. It contains no encryption, propagation, or persistence logic and
  is what you'd replace with real EDR telemetry / a sandboxed detonation
  environment in production.
- Real crypto-API and mass-handle-open hooking requires OS-level
  instrumentation (ETW on Windows, eBPF/auditd on Linux) running with
  elevated privileges — out of scope for a portable prototype, so
  `collector.py` exposes the same event shape that layer would feed and
  documents the boundary explicitly.
- The RandomForest is trained on synthetic feature distributions grounded
  in published ransomware-behavior characteristics (near-maximal output
  entropy, high file-touch rate, mass renames) vs. normal office workloads.
  A production system would train on labeled EDR telemetry / sandbox
  detonation data instead.

## Two bugs fixed during development (documented for the report)

1. **Read/rename race** — a file could be renamed between a write event
   firing and the entropy read happening, producing a silent `0.0` sample
   that dragged the running average down. Fixed by returning `None` (not
   `0.0`) on unreadable files and having callers skip `None` samples
   (`features.safe_read_entropy`).
2. **Averaging dilution** — averaging every entropy sample (including
   stale pre-write reads) diluted the signal across many files. Fixed by
   tracking only the *latest* entropy per file per process
   (`features.LatestEntropyTracker`), and by computing entropy on the
   post-rename (final, post-encryption) file content rather than the
   pre-rename snapshot.
