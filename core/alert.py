"""
Detection and alerting layer.

Combined rule+ML risk score crosses a threshold -> fires an alert with
the offending PID and affected paths. This is the actionable output a
SOC dashboard or endpoint agent would consume to kill/quarantine.
"""

import time
from dataclasses import dataclass, field


@dataclass
class Alert:
    ts: float
    pid: int
    risk_score: float
    rule_score: float
    ml_score: float
    reasons: list
    affected_paths: list = field(default_factory=list)

    def to_dict(self):
        return {
            "timestamp": self.ts,
            "pid": self.pid,
            "risk_score": self.risk_score,
            "rule_score": self.rule_score,
            "ml_score": self.ml_score,
            "reasons": self.reasons,
            "affected_paths": self.affected_paths,
            "recommended_action": "isolate/kill process and quarantine affected paths",
        }


class AlertManager:
    def __init__(self, threshold: float = 0.5, cooldown_seconds: float = 5.0):
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        self._last_alert_ts = {}
        self.alerts = []

    def evaluate(self, risk_result: dict, affected_paths: list) -> "Alert | None":
        pid = risk_result["pid"]
        now = risk_result["ts"]

        if risk_result["risk_score"] < self.threshold:
            return None

        last = self._last_alert_ts.get(pid, 0)
        if now - last < self.cooldown_seconds:
            return None  # cooldown, avoid alert storm

        alert = Alert(
            ts=now,
            pid=pid,
            risk_score=risk_result["risk_score"],
            rule_score=risk_result["rule_score"],
            ml_score=risk_result["ml_score"],
            reasons=risk_result["reasons"],
            affected_paths=affected_paths,
        )
        self._last_alert_ts[pid] = now
        self.alerts.append(alert)
        return alert
