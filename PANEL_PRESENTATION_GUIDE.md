# 🛡️ Enterprise EDR Ransomware Detection Platform
## Official Panel Presentation & Live Demonstration Guide

---

### 📌 Quick Start for Presenters
To start the entire demonstration with a single click:
- Double-click **`start_demo.bat`** (or run `.\start_demo.ps1` in PowerShell).
- The **FastAPI Backend (Port 8000)** and **TanStack React Console (Port 8081)** will launch automatically.
- Your default web browser will open straight to **`http://localhost:8081/`**.

---

## 1. Executive Summary & Problem Statement (1 Minute Pitch)

> *"Traditional Antivirus solutions rely heavily on signature matching and known file hashes. Modern ransomware—such as LockBit, BlackCat, or polymorphic zero-day variants—modifies its binary structure and encrypts gigabytes of data before signature definitions can ever be updated.*
>
> *Our project introduces an **Endpoint Detection & Response (EDR) platform** that detects ransomware **purely through real-time behavioral telemetry and machine learning**. By analyzing Shannon entropy shifts, file renaming velocities, magic byte mutations, and process I/O rates, we detect and neutralize ransomware within seconds—before irreversible data loss occurs."*

---

## 2. Core Architecture Overview

Our system operates as an end-to-end, multi-stage detection pipeline:

```
┌─────────────────┐       ┌──────────────────────┐       ┌────────────────────────┐
│  Stage 1:       │  ==>  │  Stage 2:            │  ==>  │  Stage 3:              │
│  Data Collector │       │  Feature Extraction  │       │  Dual-Engine Scoring   │
│  (Watchdog / IO)│       │  (Entropy, Rnames)   │       │  (Rules + ML RF Model) │
└─────────────────┘       └──────────────────────┘       └────────────────────────┘
                                                                      │
                                                                      ▼
┌─────────────────┐       ┌──────────────────────┐       ┌────────────────────────┐
│  Stage 5:       │  <==  │  Stage 4:            │  <==  │  Automated Mitigation  │
│  Forensics &    │       │  Correlation &       │       │  & Alert Manager       │
│  Incident Report│       │  MITRE ATT&CK Triage │       │  (Process Kill/Quar.)  │
└─────────────────┘       └──────────────────────┘       └────────────────────────┘
```

1. **Stage 1 — Telemetry Collector (`core.collector`)**: Hooks file system events and monitored process telemetry (I/O, CPU, handle count).
2. **Stage 2 — Feature Extraction (`core.features`)**: Real-time statistical evaluation:
   - **Shannon Entropy**: Measures randomness ($H = -\sum p_i \log_2 p_i$). Plaintext is $\approx 3.5 - 4.8$; encrypted files surge to $\approx 7.8 - 8.0$.
   - **Extension Alteration Frequency**: Tracks suspicious extensions (`.locked`, `.crypto`, `.enc`).
   - **Operation Velocity**: Tracks file write/rename burst rates.
3. **Stage 3 — Dual-Engine Behavioral Scoring (`core.engine`)**:
   - **Rule-Based Engine**: Catches known malicious heuristics with deterministic thresholds.
   - **Random Forest ML Classifier**: Evaluates multi-dimensional behavioral vectors trained on benign vs ransomware workloads.
   - **Ensemble Risk Score**: Weighted fusion ($0.5 \times \text{Rule} + 0.5 \times \text{ML}$) bounded from `0.000` to `1.000`.
4. **Stage 4 — Alerting & Autonomous Mitigation (`core.alert`, `backend.mitigation`)**:
   - Fires high-priority alerts when risk crosses the threshold ($> 0.60$).
   - Can isolate the endpoint, terminate rogue process trees, and quarantine affected paths.
5. **Stage 5 — Forensic Reconstruction (`core.forensics`)**:
   - Generates immutable JSON/HTML incident reports with full chronological evidence timelines and MITRE ATT&CK mapping.

---

## 3. Step-by-Step Live Demo Script (5 Minutes)

Follow these exact steps when demonstrating to the panel:

### 🟢 Step 1: System Baseline & Executive Overview (30 seconds)
1. Point to the **top navigation bar**:
   - Show `AEGIS v2.0 EDR` with status `SYSTEM ARMED` (Green indicator).
   - Point to the quick simulation buttons: **`Normal Test`** and **`Simulate Attack`**.
2. Point to the **Threat Risk Level Card**:
   - Show the current baseline score (`0.000` / `SAFE / NOMINAL`) with threshold reference (`0.60`).
   - Point to the **5-Stage Autonomous Pipeline Stepper**:
     - `01 Telemetry` $\rightarrow$ `02 Features` $\rightarrow$ `03 Dual ML` $\rightarrow$ `04 Correlation` $\rightarrow$ `05 Forensics`.
3. **Panel Talking Point**: *"The console is designed as a minimal, high-impact SOC triage interface that surfaces core behavioral signals without cognitive clutter."*

---

### 🟡 Step 2: Benign Workload Demonstration (1 minute)
1. Click the **`Normal Test`** button in the header.
2. Watch the dashboard update:
   - Target process updates to normal background workload.
   - Stepper advances through Telemetry $\rightarrow$ Features $\rightarrow$ Dual ML.
   - Shannon entropy remains low ($\approx 3.2 - 4.1$), and the risk score remains nominal.
   - **Zero alerts** appear in the *Live Telemetry* tab.
3. **Panel Talking Point**: *"This proves our model does not suffer from false-positive fatigue during normal administrative or office file operations."*

---

### 🔴 Step 3: Real-Time Ransomware Attack Simulation (1.5 minutes)
1. Click the **`Simulate Attack`** button in the header.
2. Direct the panel's attention to the live meters:
   - Header badge changes to **`THREAT ACTIVE`** (pulsing red).
   - The **Threat Risk Level surges** past `0.60` up to **`0.960`** (`CRITICAL MALICIOUS`).
   - Active Alerts counter updates instantly.
3. In the **Live Telemetry** tab:
   - A critical alert appears: `CRITICAL · crypto_locker.exe (PID XXXX)`.
   - Telemetry signals show: *High entropy write burst ($> 7.5$ bits/byte)* and *Mass file extension substitutions to `.locked`*.
4. **Panel Talking Point**: *"Within less than 2 seconds, our behavioral engine caught the encryption pattern and generated actionable detection without needing any prior file signature or cloud lookup."*

---

### 🔍 Step 4: Interactive File Inspector & Real-Time Upload (1 minute)
1. Switch to the **`File Inspector`** tab.
2. You have **two seamless demonstration methods**:
   - **Method A (Instant 1-Click)**: Click **`Test Clean Sample`** (shows $H \approx 4.76$, Score `0.000`, `VERDICT: CLEAN`), then click **`Test Encrypted Ransomware`** (shows $H \approx 7.98$, Score `1.000`, `VERDICT: MALICIOUS`).
   - **Method B (File Upload from Disk)**: Click **`Choose Files from Disk`** or drag & drop files from the provided **[`demo_samples/`](file:///d:/ransom_web/ransom_detector/demo_samples/)** folder:
     - `clean_audit_report.txt` $\rightarrow$ Plaintext, nominal entropy ($4.6$ bits/byte).
     - `clean_employee_roster.csv` $\rightarrow$ Structured data, low entropy ($3.9$ bits/byte).
     - `financial_data.xlsx.locked` $\rightarrow$ Encrypted payload, near-maximum entropy ($7.99$ bits/byte).
     - `customer_database.db.crypto` $\rightarrow$ Encrypted binary payload ($7.98$ bits/byte).
3. Point out the resulting analysis:
   - **Shannon Entropy Bar**: Visual color-coded gauge from $0.00 \to 8.00$ bits/byte.
   - **Magic Byte Header Inspection**: Checks true MIME signature against file extension to detect masquerading.
   - **Automated AI Threat Classification**:
     - Likely Ransomware Family Classification (*LockBit / Automated File Encryptor*).
     - Automated **MITRE ATT&CK** mapping (`T1486 Data Encrypted for Impact`, `T1027 Obfuscated Files`).
     - Prescribed SOC containment actions.
   - **`Export JSON`**: Click to show the machine-readable forensic artifact.
4. **Panel Talking Point**: *"Security analysts can detonate and inspect suspicious incoming binaries or encrypted artifacts directly in the console with zero auxiliary memory overhead ($O(1)$ streaming histogram) and automated MITRE mapping."*

---

### 📑 Step 5: Incident Forensics & MLOps Engine (1 minute)
1. Switch to the **`Incident Forensics`** tab:
   - Click **`View Details`** on the latest incident report to open the modal.
   - Show the second-by-second **Evidence Timeline** and click **`Export JSON`** for SIEM export.
2. Switch to the **`Model & Engine`** tab:
   - Point out the active model metrics (Accuracy, Precision, Recall, F1 score).
   - Show the key feature importance weights (Shannon Entropy $34.2\%$, Rename Velocity $28.5\%$, Extension Alteration $21.0\%$).
   - Point to the **`Trigger Model Retrain`** button to demonstrate continuous MLOps.
3. **Panel Talking Point**: *"The platform combines detection with complete forensic reproducibility and continuous model retraining."*

---

## 4. Anticipated Panel Questions & Answers (Cheat Sheet)

### Q1: *"How does your system distinguish ransomware from legitimate encryption tools like 7-Zip, BitLocker, or VeraCrypt?"*
> **Answer**:
> *"Legitimate tools like 7-Zip are initiated by an interactive user or known signed binaries, typically write to a single output archive, and do not systematically delete, overwrite, and rename hundreds of existing files in user document directories. In contrast, ransomware exhibits a distinctive pattern: mass sequential file traversal, in-place overwriting with high entropy, appending ransom notes (`README_RESTORE.txt`), and batch renaming to custom extensions. Our multi-dimensional Random Forest model correlates these concurrent behavioral features rather than relying on entropy alone."*

### Q2: *"What is the computational and memory overhead on the host machine?"*
> **Answer**:
> *"The agent is engineered for low footprint. Our file scanner uses streaming chunked buffers with an online 256-bin byte frequency histogram, requiring only $O(1)$ auxiliary memory (less than 1 KB of RAM) regardless of whether the file is 10 KB or 50 MB. Telemetry queues use non-blocking asynchronous dequeuing, maintaining under 2% average CPU utilization."*

### Q3: *"How does the system prevent model drift or adapt to novel ransomware behaviors?"*
> **Answer**:
> *"We have implemented a continuous MLOps feedback loop (`mlops/retrain_pipeline.py`). When SOC analysts review an alert, they can submit True Positive or False Positive feedback directly through the API. The system stores verified samples in SQLite and can trigger automated model retraining with dataset versioning, generating an updated classifier without downtime."*

### Q4: *"Can sophisticated ransomware evade this by encrypting files slowly (slow-and-low attack)?"*
> **Answer**:
> *"Slow-and-low ransomware is a known evasion technique. To counter this, our feature extraction maintains both a short-term sliding window (for rapid bursts) and cumulative file entropy history across the lifecycle of the process. Even if encryption is spaced out over minutes, the persistent entropy increase of user documents and cumulative extension mutations will trigger the behavioral engine once the volume exceeds baseline thresholds."*

### Q5: *"What are the key machine learning features used by the Random Forest model?"*
> **Answer**:
> 1. `mean_entropy`: Average Shannon entropy across modified files.
> 2. `entropy_variance`: Uniformity of randomness across byte blocks.
> 3. `file_rename_rate`: Frequency of filename/extension modifications per unit time.
> 4. `touched_file_count`: Total number of distinct documents targeted.
> 5. `extension_change_count`: Count of substitutions to known or randomized ransomware extensions.
> 6. `io_write_bytes_sec`: Burst write throughput.

---

## 5. Technology Stack Summary Table

| Layer | Technologies Used | Key Responsibilities |
|---|---|---|
| **Frontend Console** | React 19, TanStack Start, Tailwind CSS, Lucide, Recharts | Real-time EDR dashboard, simulation controls, forensic report viewer, file scanner |
| **Backend API** | FastAPI, Uvicorn, Asynchronous WebSockets | REST API endpoints, real-time telemetry streaming, pipeline service orchestration |
| **Detection Core** | Python 3.12, scikit-learn, NumPy | Shannon entropy computation, feature extraction, Random Forest classifier, rule engine |
| **Data & Storage** | SQLite / aiosqlite, Pydantic v2 | Incident logs, scan history, agent registrations, feedback store |
| **MLOps Pipeline** | scikit-learn, joblib, synthetic generator | Automated retraining, hyperparameter verification, model versioning |

---
*Ready to present! Good luck with your panel presentation!*
