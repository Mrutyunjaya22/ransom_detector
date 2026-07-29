import glob
import json
import os
import subprocess
import sys
import threading
import time
from typing import Any

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from core.alert import AlertManager
from core.collector import Collector
from core.engine import BehavioralEngine
from core.forensics import generate_incident_report

SANDBOX_DIR = os.path.join(ROOT, "test_sandbox")
MODEL_PATH = os.path.join(ROOT, "models", "rf_classifier.pkl")
REPORTS_DIR = os.path.join(ROOT, "reports")
POLL_INTERVAL = 1.0
RUN_DURATION_SECONDS = 30.0
STAGES = [
    "collecting",
    "feature-extraction",
    "scoring",
    "correlating",
    "reporting",
]


def _load_report(path: str) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


class PipelineService:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.mode: str = "idle"
        self.stage: str = "idle"
        self.events_processed = 0
        self.model_loaded = os.path.exists(MODEL_PATH)
        self.collector_active = False
        self.monitor_process = {"name": "", "pid": 0}
        self.score = 0.0
        self.threshold = 0.6
        self.alerts: list[dict[str, Any]] = []
        self.reports: list[dict[str, Any]] = self._load_reports()
        self.last_observation: dict[str, Any] = {}
        self.analysis_evidence: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._collector: Collector | None = None
        self._engine: BehavioralEngine | None = None
        self._alert_manager: AlertManager | None = None
        self._process: subprocess.Popen | None = None
        self._run_started_at: float | None = None
        self._highest_alert: dict[str, Any] | None = None

    def _load_reports(self) -> list[dict[str, Any]]:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        reports = []
        for path in sorted(glob.glob(os.path.join(REPORTS_DIR, "*.json")), reverse=True):
            report = _load_report(path)
            if report is not None:
                reports.append(report)
        return reports

    def _get_pid(self) -> int | None:
        return self.monitor_process.get("pid") or None

    def _load_report_file(self, path: str) -> dict[str, Any] | None:
        report = _load_report(path)
        if report is not None:
            self.reports.insert(0, report)
            self.reports = self.reports[:25]
        return report

    def _update_stage(self) -> None:
        if self.mode == "idle" or self._run_started_at is None:
            self.stage = "idle"
            return
        elapsed = time.time() - self._run_started_at
        idx = min(int(elapsed / (RUN_DURATION_SECONDS / len(STAGES))), len(STAGES) - 1)
        self.stage = STAGES[idx]

    def _make_alert(self, alert: Any) -> dict[str, Any]:
        result = {
            "timestamp": alert.ts,
            "pid": alert.pid,
            "risk_score": alert.risk_score,
            "rule_score": alert.rule_score,
            "ml_score": alert.ml_score,
            "reasons": alert.reasons,
            "affected_paths": alert.affected_paths,
            "recommended_action": "isolate/kill process and quarantine affected paths",
        }
        return result

    def _build_active_stages(self) -> list[dict[str, Any]]:
        stage_names = STAGES
        if self.mode == "idle":
            return [
                {"name": stage, "status": "pending", "detail": "Awaiting workload"}
                for stage in stage_names
            ]

        current_idx = stage_names.index(self.stage) if self.stage in stage_names else len(stage_names) - 1
        stages: list[dict[str, Any]] = []
        for idx, stage_name in enumerate(stage_names):
            if idx < current_idx:
                status = "complete"
                detail = self._stage_detail(stage_name)
            elif idx == current_idx:
                status = "active"
                detail = self._stage_detail(stage_name)
            else:
                status = "pending"
                detail = "Queued"
            stages.append({"name": stage_name, "status": status, "detail": detail})
        return stages

    def _stage_detail(self, stage_name: str) -> str:
        if stage_name == "collecting":
            return f"{self.events_processed} events buffered for analysis"
        if stage_name == "feature-extraction":
            features = self.last_observation.get("features", {}) or {}
            if features:
                return (
                    f"entropy {features.get('mean_entropy', 0):.1f} • "
                    f"touched files {int(features.get('touched_file_count', 0))}"
                )
            return "Extracting entropy, rename and process behavior vectors"
        if stage_name == "scoring":
            if self.last_observation:
                return (
                    f"risk {self.last_observation.get('risk_score', 0):.2f} • "
                    f"rule {self.last_observation.get('rule_score', 0):.2f}"
                )
            return "Scoring the feature window with rule and ML layers"
        if stage_name == "correlating":
            reasons = self.last_observation.get("reasons", []) or []
            if reasons:
                return f"{len(reasons)} suspicious signal(s) correlated"
            return "Correlating suspicious file and process behavior"
        if stage_name == "reporting":
            if self._highest_alert or self.reports:
                return "Forensic reconstruction report prepared"
            return "Preparing incident reconstruction and evidence timeline"
        return "Queued"

    def _record_observation(self, result: dict[str, Any]) -> None:
        self.last_observation = result
        features = result.get("features", {}) or {}
        reasons = result.get("reasons", []) or []
        risk_score = float(result.get("risk_score", 0.0) or 0.0)
        severity = "low"
        if risk_score >= 0.8:
            severity = "critical"
        elif risk_score >= 0.6:
            severity = "high"
        elif risk_score >= 0.35:
            severity = "medium"

        self.analysis_evidence.insert(
            0,
            {
                "timestamp": result.get("ts", time.time()),
                "stage": self.stage,
                "title": "Behavioral signal updated",
                "detail": (
                    f"risk {risk_score:.2f} | rule {result.get('rule_score', 0):.2f} | "
                    f"ml {result.get('ml_score', 0):.2f}"
                ),
                "severity": severity,
                "signals": reasons,
                "features": features,
            },
        )
        self.analysis_evidence = self.analysis_evidence[:8]

    def status_payload(self) -> dict[str, Any]:
        return {
            "pipeline": {
                "healthy": self.model_loaded and self.collector_active,
                "stage": self.stage,
                "mode": self.mode,
                "uptimeSec": int(time.time() - self.started_at),
                "eventsProcessed": self.events_processed,
            },
            "modelLoaded": self.model_loaded,
            "collectorActive": self.collector_active,
            "monitoredProcess": self.monitor_process,
            "riskScore": round(self.score, 3),
            "threshold": self.threshold,
            "alertCount": len(self.alerts),
            "analysis": {
                "currentStage": self.stage,
                "activeStages": self._build_active_stages(),
                "evidence": self.analysis_evidence,
                "summary": {
                    "riskScore": round(self.score, 3),
                    "ruleScore": round(self.last_observation.get("rule_score", 0.0), 3),
                    "mlScore": round(self.last_observation.get("ml_score", 0.0), 3),
                    "eventsProcessed": self.events_processed,
                    "suspiciousSignals": len(self.last_observation.get("reasons", []) or []),
                    "forensicReady": bool(self._highest_alert or self.reports),
                },
            },
        }

    def get_alerts(self) -> list[dict[str, Any]]:
        return self.alerts[:20]

    def get_reports(self) -> list[dict[str, Any]]:
        return [
            {
                "id": report.get("incident_id", ""),
                "mode": report.get("mode", "unknown"),
                "verdict": report.get("verdict", "unknown"),
                "peakScore": report.get("risk_score", 0.0),
                "alertCount": len(report.get("trigger_reasons", [])),
                "createdAt": report.get("generated_at", ""),
                "process": report.get("process_id", 0),
            }
            for report in self.reports
        ]

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        for report in self.reports:
            if report.get("incident_id") == report_id:
                return report
        # load from disk if not already in memory
        report_path = os.path.join(REPORTS_DIR, f"{report_id}.json")
        return self._load_report_file(report_path)

    def start_run(self, mode: str) -> dict[str, Any]:
        with self._lock:
            if self.mode != "idle":
                raise RuntimeError("Pipeline is already running")
            if mode not in ("benign", "attack"):
                raise ValueError("mode must be 'benign' or 'attack'")

            self.mode = mode
            self.stage = "collecting"
            self.events_processed = 0
            self.score = 0.0
            self.alerts = []
            self._highest_alert = None
            self._run_started_at = time.time()

            self._engine = BehavioralEngine(MODEL_PATH)
            self._alert_manager = AlertManager(threshold=self.threshold)
            self._collector = Collector(SANDBOX_DIR, self._get_pid)
            self._collector.start()
            self.collector_active = True

            script = os.path.join(ROOT, "simulate_activity.py")
            self._process = subprocess.Popen(
                [sys.executable, script, mode, SANDBOX_DIR],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.monitor_process = {
                "name": "ransom_simulator.exe",
                "pid": self._process.pid,
            }

            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            return {
                "mode": self.mode,
                "stage": self.stage,
                "process": self.monitor_process,
                "durationSec": RUN_DURATION_SECONDS,
            }

    def _drain_queue(self) -> None:
        if not self._collector or not self._engine or not self._alert_manager:
            return
        while True:
            try:
                event = self._collector.queue.get_nowait()
            except Exception:
                break
            self._engine.ingest(event)
            self.events_processed += 1
            pid = self.monitor_process.get("pid")
            if pid:
                result = self._engine.risk_score(pid)
                self.score = result["risk_score"]
                self._record_observation(result)
                affected = list(self._engine.entropy_tracker._latest.get(pid, {}).keys())
                alert = self._alert_manager.evaluate(result, affected)
                if alert:
                    alert_dict = self._make_alert(alert)
                    self.alerts.insert(0, alert_dict)
                    self._highest_alert = alert_dict

    def _run_loop(self) -> None:
        if self._process is None:
            return
        try:
            while self._process.poll() is None or (self._collector and not self._collector.queue.empty()):
                self._drain_queue()
                self._update_stage()
                time.sleep(POLL_INTERVAL)
            self._drain_queue()
            if self._highest_alert and self._engine is not None:
                # generate report after the run completes
                report_path = generate_incident_report(
                    self._highest_alert, self._engine, REPORTS_DIR
                )
                self._load_report_file(report_path)
        finally:
            self._stop_run()

    def _stop_run(self) -> None:
        if self._collector is not None:
            try:
                self._collector.stop()
            except Exception:
                pass
        self.collector_active = False
        self.stage = "idle"
        self.mode = "idle"
        self.monitor_process = {"name": "", "pid": 0}
        self._process = None
        self._run_started_at = None


pipeline_service = PipelineService()
