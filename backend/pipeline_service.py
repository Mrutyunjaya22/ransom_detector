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
        self.scans: list[dict[str, Any]] = []
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
        risk_score = float(getattr(alert, "risk_score", 0.0) or 0.0)
        score = round(risk_score, 3)
        if score >= 0.8:
            severity = "critical"
        elif score >= 0.6:
            severity = "high"
        elif score >= 0.35:
            severity = "medium"
        else:
            severity = "low"

        ts = float(getattr(alert, "ts", time.time()))
        created_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        proc_name = self.monitor_process.get("name") or "ransom_simulator.exe"
        pid = int(getattr(alert, "pid", 0) or 0)
        alert_id = f"ALT-{int(ts)}-{pid}"

        result = {
            "id": alert_id,
            "severity": severity,
            "process": proc_name,
            "pid": pid,
            "score": score,
            "reasons": list(getattr(alert, "reasons", [])),
            "createdAt": created_at,
            "timestamp": ts,
            "risk_score": risk_score,
            "rule_score": float(getattr(alert, "rule_score", 0.0) or 0.0),
            "ml_score": float(getattr(alert, "ml_score", 0.0) or 0.0),
            "affected_paths": list(getattr(alert, "affected_paths", [])),
            "recommended_action": "isolate/kill process and quarantine affected paths",
        }
        return result

    def add_scan(self, scan_item: dict[str, Any]) -> None:
        self.scans.insert(0, scan_item)
        self.scans = self.scans[:50]
        try:
            from backend.repository import edr_repo
            edr_repo.save_scan_background(scan_item)
        except Exception:
            pass

    def get_scans(self) -> list[dict[str, Any]]:
        return self.scans

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
                "healthy": self.model_loaded,
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
        results = []
        for report in self.reports:
            peak = float(report.get("risk_score", 0.0) or 0.0)
            mode = report.get("mode") or ("attack" if peak >= 0.5 else "benign")
            verdict = "malicious" if peak >= 0.6 else "suspicious" if peak >= 0.35 else "clean"
            reasons = report.get("trigger_reasons", [])
            results.append({
                "id": report.get("incident_id", ""),
                "mode": mode,
                "verdict": verdict,
                "peakScore": round(peak, 3),
                "alertCount": len(reasons),
                "createdAt": report.get("generated_at", ""),
                "process": str(report.get("process_id", 0)),
            })
        return results

    def _format_report_detail(self, report: dict[str, Any]) -> dict[str, Any]:
        peak_score = float(report.get("risk_score", 0.0) or 0.0)
        if peak_score >= 0.6:
            verdict = "malicious"
        elif peak_score >= 0.35:
            verdict = "suspicious"
        else:
            verdict = "clean"

        pid = int(report.get("process_id", 0) or 0)
        created_at = str(report.get("generated_at", ""))
        reasons = list(report.get("trigger_reasons", []))
        mode = report.get("mode") or ("attack" if peak_score >= 0.5 else "benign")

        alerts_list = []
        for idx, reason in enumerate(reasons):
            alerts_list.append({
                "id": f"ALT-{report.get('incident_id', 'rep')}-{idx}",
                "severity": "critical" if peak_score >= 0.8 else "high" if peak_score >= 0.6 else "medium",
                "process": report.get("process_name", "ransom_simulator.exe"),
                "pid": pid,
                "score": round(peak_score, 3),
                "reasons": [reason],
                "createdAt": created_at,
            })

        raw_timeline = report.get("event_timeline", [])
        timeline = []
        for idx, item in enumerate(raw_timeline[:60]):
            raw_path = item.get("path") or item.get("dest_path") or ""
            base_path = os.path.basename(raw_path) if raw_path else "file"
            timeline.append({
                "t": round(idx * 0.1, 1),
                "score": round(peak_score, 2),
                "event": f"{item.get('event', 'fs_event')} — {base_path}",
            })
        if not timeline:
            timeline = [{"t": 0.0, "score": round(peak_score, 2), "event": "workload initialized"}]

        features = report.get("features") or self.last_observation.get("features", {}) or {}
        if not features:
            trend = report.get("entropy_trend", [])
            mean_ent = (
                sum(t.get("entropy", 0.0) for t in trend) / max(len(trend), 1)
                if trend
                else (7.8 if peak_score >= 0.6 else 4.2)
            )
            features = {
                "mean_entropy": round(mean_ent, 2),
                "touched_file_count": len(trend) or len(report.get("affected_paths", [])),
                "high_entropy_fraction": 0.88 if peak_score >= 0.6 else 0.04,
                "ext_change_rate": 3.4 if peak_score >= 0.6 else 0.0,
                "file_op_rate": 6.2 if peak_score >= 0.6 else 1.2,
                "cpu_percent": 78.0 if peak_score >= 0.6 else 12.0,
                "io_bytes_per_s": 240000.0 if peak_score >= 0.6 else 15000.0,
            }

        return {
            **report,
            "id": report.get("incident_id", ""),
            "mode": mode,
            "verdict": verdict,
            "peakScore": round(peak_score, 3),
            "alertCount": len(reasons),
            "createdAt": created_at,
            "process": report.get("process_name", "ransom_simulator.exe"),
            "pid": pid,
            "durationSec": int(report.get("duration_sec", 30)),
            "features": features,
            "timeline": timeline,
            "alerts": alerts_list,
            "recommendation": report.get(
                "recommended_action",
                "Isolate or terminate the process and quarantine affected directories.",
            ),
        }

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        target = None
        for report in self.reports:
            if report.get("incident_id") == report_id or report.get("id") == report_id:
                target = report
                break
        if target is None:
            # load from disk if not already in memory
            report_path = os.path.join(REPORTS_DIR, f"{report_id}.json")
            target = self._load_report_file(report_path)
        if target is not None:
            return self._format_report_detail(target)
        return None

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

                    # Real-time WebSocket Alert Broadcast
                    try:
                        from backend.websocket_manager import ws_manager, ChannelType
                        ws_manager.broadcast_sync(ChannelType.ALERTS, "alert_raised", alert_dict)
                    except Exception:
                        pass

                    # Persist alert to relational database
                    try:
                        from backend.repository import edr_repo
                        edr_repo.save_alert_background(alert_dict)
                    except Exception:
                        pass

                    # Active Mitigation: immediately freeze and terminate process tree when risk >= 0.85
                    if alert.risk_score >= 0.85 and pid:
                        try:
                            from backend.mitigation import process_mitigator
                            mitigation_res = process_mitigator.terminate_process_tree(
                                target_pid=pid,
                                trigger_reason="; ".join(alert.reasons),
                                risk_score=alert.risk_score,
                            )
                            from backend.websocket_manager import ws_manager, ChannelType
                            ws_manager.broadcast_sync(
                                ChannelType.MITIGATION,
                                "mitigation_executed",
                                mitigation_res.to_dict(),
                            )
                        except Exception:
                            pass

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
                try:
                    with open(report_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    data["mode"] = self.mode
                    data["features"] = self.last_observation.get("features", {})
                    data["process_name"] = self.monitor_process.get("name", "ransom_simulator.exe")
                    with open(report_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, default=str)
                except Exception:
                    pass
                self._load_report_file(report_path)
                try:
                    from backend.repository import edr_repo
                    edr_repo.save_report_background(self._format_report_detail(data))
                except Exception:
                    pass
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
