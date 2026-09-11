"""
Behavioral analysis engine.

Consumes raw events from the Collector queue, aggregates them into a
per-process sliding-window feature vector, and scores that vector with
two complementary layers:

  - Rule layer: fast, explainable, catches obvious spikes
        (entropy jump + mass rename inside the window)
  - ML layer: RandomForestClassifier scores subtler patterns using the
        same feature vector (trained by train_model.py on synthetic
        benign vs. ransomware-like feature distributions)

Rule and ML scores are combined into a single 0-1 risk score.
"""

import os
import pickle
import time
from collections import defaultdict, deque

import numpy as np

from .features import ExtensionTracker, LatestEntropyTracker, safe_read_entropy

WINDOW_SECONDS = 10.0
FEATURE_NAMES = [
    "file_op_rate",          # file operations / second in window
    "mean_entropy",          # mean entropy of latest file content per touched file
    "high_entropy_fraction", # fraction of touched files with entropy >= 7.5
    "ext_change_rate",       # extension changes / second
    "suspicious_ext_rate",   # suspicious-extension changes / second
    "cpu_percent",           # latest CPU% sample for the process
    "children_spawned",      # latest child-process count
    "io_bytes_per_s",        # latest IO throughput sample
    "touched_file_count",    # distinct files touched in window
]


class SlidingWindow:
    """Per-process ring buffer of (timestamp, event) pairs over WINDOW_SECONDS."""

    def __init__(self, window_seconds: float = WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.events = defaultdict(deque)  # pid -> deque[(ts, event)]

    def add(self, pid: int, ts: float, event):
        dq = self.events[pid]
        dq.append((ts, event))
        self._evict(pid, ts)

    def _evict(self, pid: int, now: float):
        dq = self.events[pid]
        while dq and now - dq[0][0] > self.window_seconds:
            dq.popleft()

    def get(self, pid: int):
        return list(self.events.get(pid, []))


class RuleEngine:
    """Fast, explainable spike detector."""

    def score(self, features: dict) -> float:
        score = 0.0
        reasons = []

        if features["high_entropy_fraction"] >= 0.6 and features["file_op_rate"] >= 3:
            score += 0.55
            reasons.append("entropy jump + mass file writes in window")

        if features["suspicious_ext_rate"] > 0:
            score += 0.35
            reasons.append("suspicious extension pattern (e.g. .docx -> .locked)")

        if features["ext_change_rate"] >= 2 and features["touched_file_count"] >= 5:
            score += 0.25
            reasons.append("high-rate mass rename across many files")

        if features["children_spawned"] >= 3:
            score += 0.1
            reasons.append("unusual child-process fan-out")

        return min(score, 1.0), reasons


class MLScorer:
    """Wraps the trained RandomForestClassifier."""

    def __init__(self, model_path: str):
        self.model = None
        self.model_path = model_path
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)

    def score(self, features: dict) -> float:
        if self.model is None:
            return 0.0
        vec = np.array([[features[name] for name in FEATURE_NAMES]])
        proba = self.model.predict_proba(vec)[0]
        # class 1 == "ransomware-like"
        classes = list(self.model.classes_)
        idx = classes.index(1) if 1 in classes else int(np.argmax(proba))
        return float(proba[idx])


class BehavioralEngine:
    def __init__(self, model_path: str, window_seconds: float = WINDOW_SECONDS,
                 rule_weight: float = 0.5, ml_weight: float = 0.5):
        self.window = SlidingWindow(window_seconds)
        self.ext_tracker = ExtensionTracker()
        self.entropy_tracker = LatestEntropyTracker()
        self.rule_engine = RuleEngine()
        self.ml_scorer = MLScorer(model_path)
        self.rule_weight = rule_weight
        self.ml_weight = ml_weight
        self.last_cpu = defaultdict(float)
        self.last_children = defaultdict(int)
        self.last_io = defaultdict(float)
        # Buffer of ALL events per pid (not window-evicted) for forensic replay.
        self.forensic_log = defaultdict(list)

    def ingest(self, event):
        pid = event.pid
        if pid is None:
            return
        self.window.add(pid, event.ts, event)
        self.forensic_log[pid].append(event)

        extra = getattr(event, "extra", {}) or {}

        if event.kind in ("fs_create", "fs_modify"):
            entropy = extra.get("entropy") if "entropy" in extra else safe_read_entropy(event.path)
            self.entropy_tracker.update(pid, event.path, entropy)
        elif event.kind == "fs_rename":
            self.ext_tracker.record_rename(pid, event.path, event.dest_path)
            entropy = extra.get("entropy") if "entropy" in extra else safe_read_entropy(event.dest_path)
            if entropy is not None:
                self.entropy_tracker.update(pid, event.dest_path, entropy)
        elif event.kind in ("proc_sample", "proc_snapshot"):
            self.last_cpu[pid] = extra.get("cpu_percent") or self.last_cpu[pid]
            self.last_children[pid] = extra.get("children") or extra.get("num_children") or self.last_children[pid]
            self.last_io[pid] = extra.get("io_bytes_per_s") or self.last_io[pid]

    def compute_features(self, pid: int) -> dict:
        window_events = self.window.get(pid)
        fs_events = [e for _, e in window_events if e.kind.startswith("fs_")]
        span = self.window.window_seconds

        file_op_rate = len(fs_events) / span if span else 0.0
        ext_change_rate = self.ext_tracker.rate(pid, span)
        suspicious_ext_rate = self.ext_tracker.suspicious_rate(pid, span)

        return {
            "file_op_rate": file_op_rate,
            "mean_entropy": self.entropy_tracker.mean_entropy(pid),
            "high_entropy_fraction": self.entropy_tracker.high_entropy_fraction(pid),
            "ext_change_rate": ext_change_rate,
            "suspicious_ext_rate": suspicious_ext_rate,
            "cpu_percent": self.last_cpu.get(pid, 0.0),
            "children_spawned": self.last_children.get(pid, 0),
            "io_bytes_per_s": self.last_io.get(pid, 0.0),
            "touched_file_count": self.entropy_tracker.touched_file_count(pid),
        }

    def risk_score(self, pid: int):
        features = self.compute_features(pid)
        rule_score, reasons = self.rule_engine.score(features)
        ml_score = self.ml_scorer.score(features)
        combined = self.rule_weight * rule_score + self.ml_weight * ml_score
        return {
            "pid": pid,
            "ts": time.time(),
            "features": features,
            "rule_score": round(rule_score, 3),
            "ml_score": round(ml_score, 3),
            "risk_score": round(combined, 3),
            "reasons": reasons,
        }
