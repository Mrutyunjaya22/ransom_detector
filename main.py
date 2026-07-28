"""
End-to-end pipeline orchestrator.

Stage 1 Data collection      -> core.collector.Collector
Stage 2 Feature extraction   -> core.features
Stage 3 Behavioral analysis  -> core.engine.BehavioralEngine (rules + RandomForest)
Stage 4 Detection/alerting   -> core.alert.AlertManager
Stage 5 Forensic reconstruct -> core.forensics.generate_incident_report

Run: python3 main.py
"""

import os
import subprocess
import sys
import threading
import time

from core.collector import Collector
from core.engine import BehavioralEngine
from core.alert import AlertManager
from core.forensics import generate_incident_report

SANDBOX_DIR = os.path.join(os.path.dirname(__file__), "test_sandbox")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "rf_classifier.pkl")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
POLL_INTERVAL = 1.0
ALERT_THRESHOLD = 0.5


def run_pipeline(workload_fn, label: str, duration_hint: float = 8.0):
    print(f"\n{'=' * 70}\nSCENARIO: {label}\n{'=' * 70}")

    target_pid = {"pid": None}

    def pid_getter():
        return target_pid["pid"]

    collector = Collector(SANDBOX_DIR, pid_getter)
    engine = BehavioralEngine(MODEL_PATH)
    alert_mgr = AlertManager(threshold=ALERT_THRESHOLD)

    collector.start()

    # Run the workload in a subprocess so the process monitor (CPU/IO/children)
    # observes a real, distinct PID -- the same way it would observe an
    # actual endpoint process, rather than measuring the collector's own PID.
    script = "simulate_activity.py"
    mode = "benign" if label == "benign" else "attack"
    proc = subprocess.Popen(
        [sys.executable, script, mode, SANDBOX_DIR],
        cwd=os.path.dirname(__file__),
    )
    target_pid["pid"] = proc.pid
    print(f"Workload process PID: {proc.pid}")

    highest_alert = None
    start = time.time()
    while proc.poll() is None or not collector.queue.empty():
        # Drain queued events into the engine
        drained = 0
        while True:
            try:
                event = collector.queue.get_nowait()
            except Exception:
                break
            engine.ingest(event)
            drained += 1

        if target_pid["pid"] is not None:
            result = engine.risk_score(target_pid["pid"])
            bar_len = int(result["risk_score"] * 30)
            bar = "#" * bar_len + "-" * (30 - bar_len)
            print(f"  t={time.time() - start:5.1f}s  risk=[{bar}] "
                  f"{result['risk_score']:.2f}  (rule={result['rule_score']:.2f} "
                  f"ml={result['ml_score']:.2f})  files_touched="
                  f"{result['features']['touched_file_count']}")

            affected_paths = list(engine.entropy_tracker._latest.get(target_pid["pid"], {}).keys())
            alert = alert_mgr.evaluate(result, affected_paths)
            if alert:
                highest_alert = alert
                print(f"\n  *** ALERT: PID {alert.pid} risk={alert.risk_score} "
                      f"reasons={alert.reasons} ***\n")

        time.sleep(POLL_INTERVAL)
        if time.time() - start > duration_hint + 5:
            break

    proc.wait(timeout=5)
    collector.stop()

    if highest_alert:
        report_path = generate_incident_report(highest_alert, engine, REPORTS_DIR)
        print(f"Forensic incident report written: {report_path}")
    else:
        print("No alert fired for this scenario (risk stayed below threshold).")

    return highest_alert, engine


if __name__ == "__main__":
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    # Clean sandbox between runs
    for f in os.listdir(SANDBOX_DIR):
        try:
            os.remove(os.path.join(SANDBOX_DIR, f))
        except OSError:
            pass

    run_pipeline(None, "benign", duration_hint=6)

    for f in os.listdir(SANDBOX_DIR):
        try:
            os.remove(os.path.join(SANDBOX_DIR, f))
        except OSError:
            pass

    run_pipeline(None, "attack-shaped", duration_hint=6)
