"""
Forensic reconstruction layer.

Once a process is flagged, all buffered events for that PID are replayed
into an ordered timeline (which files were touched, in what order,
entropy trend over time) and written out as a JSON incident report,
which the pdf skill/report pipeline can turn into a PDF for
post-incident analysis.
"""

import json
import os
import time


def build_timeline(events: list) -> list:
    """Turn the raw forensic event buffer into an ordered, human-readable timeline."""
    timeline = []
    for e in sorted(events, key=lambda ev: ev.ts):
        entry = {
            "time": time.strftime("%H:%M:%S", time.localtime(e.ts)) + f".{int(e.ts * 1000) % 1000:03d}",
            "event": e.kind,
            "path": e.path,
        }
        if e.dest_path:
            entry["renamed_to"] = e.dest_path
        if e.extra:
            entry["details"] = e.extra
        timeline.append(entry)
    return timeline


def entropy_trend(events: list, entropy_tracker, pid: int) -> list:
    """Reconstruct entropy-over-time for touched files, in touch order."""
    trend = []
    seen = set()
    for e in sorted(events, key=lambda ev: ev.ts):
        path = e.dest_path or e.path
        if path in seen or path is None:
            continue
        latest = entropy_tracker._latest.get(pid, {})
        if path in latest:
            seen.add(path)
            trend.append({"path": path, "entropy": round(latest[path], 3)})
    return trend


def generate_incident_report(alert, engine, output_dir: str) -> str:
    """Writes a JSON incident report for the alerted process and returns its path."""
    pid = alert.pid
    events = engine.forensic_log.get(pid, [])
    timeline = build_timeline(events)
    trend = entropy_trend(events, engine.entropy_tracker, pid)

    report = {
        "incident_id": f"INC-{int(alert.ts)}-{pid}",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "process_id": pid,
        "risk_score": alert.risk_score,
        "rule_score": alert.rule_score,
        "ml_score": alert.ml_score,
        "trigger_reasons": alert.reasons,
        "affected_paths": alert.affected_paths,
        "recommended_action": "isolate/kill process and quarantine affected paths",
        "event_timeline": timeline,
        "entropy_trend": trend,
        "summary": (
            f"Process {pid} touched {len(trend)} file(s); "
            f"{sum(1 for t in trend if t['entropy'] >= 7.5)} file(s) reached "
            f"high entropy (>=7.5 bits/byte) consistent with encrypted/packed "
            f"output. Combined risk score {alert.risk_score} crossed the alert "
            f"threshold, triggering process isolation."
        ),
    }

    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{report['incident_id']}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return path
