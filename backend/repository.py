"""
Asynchronous Database Repository Layer.

Handles database transactions for alerts, reports, scans, agents, telemetry,
and analyst feedback labels.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import AsyncSessionLocal
from backend.models import (
    AgentModel,
    AlertModel,
    AnalystFeedbackModel,
    IncidentReportModel,
    ScanModel,
    TelemetryEventModel,
)


class EDRRepository:
    """Provides async database operations across all EDR subsystems."""

    @staticmethod
    async def register_agent(
        agent_id: str,
        hostname: str,
        ip_address: str,
        os_platform: str,
    ) -> AgentModel:
        """Registers a new agent or updates last heartbeat."""
        async with AsyncSessionLocal() as session:
            async with session.begin():
                agent = await session.get(AgentModel, agent_id)
                if not agent:
                    agent = AgentModel(
                        agent_id=agent_id,
                        hostname=hostname,
                        ip_address=ip_address,
                        os_platform=os_platform,
                        status="online",
                        last_heartbeat=time.time(),
                    )
                    session.add(agent)
                else:
                    agent.hostname = hostname
                    agent.ip_address = ip_address
                    agent.os_platform = os_platform
                    agent.status = "online"
                    agent.last_heartbeat = time.time()
            return agent

    @staticmethod
    async def save_alert(alert_dict: Dict[str, Any], agent_id: str = "local-agent") -> None:
        """Persists a new security alert."""
        async with AsyncSessionLocal() as session:
            async with session.begin():
                alert = AlertModel(
                    id=alert_dict["id"],
                    agent_id=agent_id,
                    timestamp=alert_dict.get("timestamp", time.time()),
                    pid=alert_dict.get("pid", 0),
                    process=alert_dict.get("process", "unknown"),
                    score=alert_dict.get("score", 0.0),
                    rule_score=alert_dict.get("rule_score", 0.0),
                    ml_score=alert_dict.get("ml_score", 0.0),
                    severity=alert_dict.get("severity", "medium"),
                    reasons=alert_dict.get("reasons", []),
                    affected_paths=alert_dict.get("affected_paths", []),
                    recommended_action=alert_dict.get("recommended_action", ""),
                    createdAt=alert_dict.get("createdAt", time.strftime("%Y-%m-%d %H:%M:%S")),
                )
                session.add(alert)

    @staticmethod
    async def get_alerts(limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent alerts ordered by timestamp descending."""
        async with AsyncSessionLocal() as session:
            stmt = select(AlertModel).order_by(desc(AlertModel.timestamp)).limit(limit)
            result = await session.execute(stmt)
            alerts = result.scalars().all()
            return [
                {
                    "id": a.id,
                    "agent_id": a.agent_id,
                    "timestamp": a.timestamp,
                    "pid": a.pid,
                    "process": a.process,
                    "score": a.score,
                    "rule_score": a.rule_score,
                    "ml_score": a.ml_score,
                    "severity": a.severity,
                    "reasons": a.reasons,
                    "affected_paths": a.affected_paths,
                    "recommended_action": a.recommended_action,
                    "createdAt": a.createdAt,
                }
                for a in alerts
            ]

    @staticmethod
    async def save_incident_report(report_dict: Dict[str, Any], agent_id: str = "local-agent") -> None:
        """Persists a forensic incident report."""
        async with AsyncSessionLocal() as session:
            async with session.begin():
                report = IncidentReportModel(
                    id=report_dict.get("id") or report_dict.get("incident_id"),
                    agent_id=agent_id,
                    mode=report_dict.get("mode", "attack"),
                    verdict=report_dict.get("verdict", "malicious"),
                    peak_score=report_dict.get("peakScore") or report_dict.get("risk_score", 0.0),
                    alert_count=report_dict.get("alertCount", 0),
                    created_at=report_dict.get("createdAt") or report_dict.get("generated_at", ""),
                    process=report_dict.get("process") or str(report_dict.get("process_id", 0)),
                    pid=int(report_dict.get("pid") or report_dict.get("process_id", 0)),
                    duration_sec=report_dict.get("durationSec", 30),
                    features=report_dict.get("features", {}),
                    timeline=report_dict.get("timeline", []),
                    recommendation=report_dict.get("recommendation", ""),
                    summary=report_dict.get("summary", ""),
                )
                await session.merge(report)

    @staticmethod
    async def get_reports(limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves summary index of recent incident reports."""
        async with AsyncSessionLocal() as session:
            stmt = select(IncidentReportModel).order_by(desc(IncidentReportModel.created_at)).limit(limit)
            result = await session.execute(stmt)
            reports = result.scalars().all()
            return [
                {
                    "id": r.id,
                    "mode": r.mode,
                    "verdict": r.verdict,
                    "peakScore": r.peak_score,
                    "alertCount": r.alert_count,
                    "createdAt": r.created_at,
                    "process": r.process,
                }
                for r in reports
            ]

    @staticmethod
    async def get_report_by_id(report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves full forensic details for a specific incident."""
        async with AsyncSessionLocal() as session:
            stmt = select(IncidentReportModel).where(IncidentReportModel.id == report_id)
            result = await session.execute(stmt)
            report = result.scalar_one_or_none()
            if not report:
                return None
            return {
                "id": report.id,
                "mode": report.mode,
                "verdict": report.verdict,
                "peakScore": report.peak_score,
                "alertCount": report.alert_count,
                "createdAt": report.created_at,
                "process": report.process,
                "pid": report.pid,
                "durationSec": report.duration_sec,
                "features": report.features,
                "timeline": report.timeline,
                "recommendation": report.recommendation,
                "summary": report.summary,
            }

    @staticmethod
    async def save_scan(scan_dict: Dict[str, Any]) -> None:
        """Persists a file scanner evaluation result."""
        async with AsyncSessionLocal() as session:
            async with session.begin():
                features_dict = scan_dict.get("features", {})
                if hasattr(features_dict, "model_dump"):
                    features_dict = features_dict.model_dump()
                scan = ScanModel(
                    id=scan_dict["id"],
                    file_name=scan_dict["fileName"],
                    size_bytes=scan_dict["sizeBytes"],
                    entropy=scan_dict["entropy"],
                    score=scan_dict["score"],
                    verdict=scan_dict["verdict"],
                    reasons=scan_dict.get("reasons", []),
                    features=features_dict,
                    scanned_at=scan_dict["scannedAt"],
                )
                session.add(scan)

    @staticmethod
    async def get_scans(limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent artifact triage scans."""
        async with AsyncSessionLocal() as session:
            stmt = select(ScanModel).order_by(desc(ScanModel.scanned_at)).limit(limit)
            result = await session.execute(stmt)
            scans = result.scalars().all()
            return [
                {
                    "id": s.id,
                    "fileName": s.file_name,
                    "sizeBytes": s.size_bytes,
                    "entropy": s.entropy,
                    "score": s.score,
                    "verdict": s.verdict,
                    "reasons": s.reasons,
                    "features": s.features,
                    "scannedAt": s.scanned_at,
                }
                for s in scans
            ]

    @staticmethod
    async def save_analyst_feedback(
        target_type: str,
        target_id: str,
        label: str,
        analyst_name: str = "analyst",
        notes: str = "",
    ) -> str:
        """Persists analyst validation labels (TP/FP) for model feedback."""
        feedback_id = f"FB-{int(time.time())}-{target_id[:8]}"
        async with AsyncSessionLocal() as session:
            async with session.begin():
                record = AnalystFeedbackModel(
                    id=feedback_id,
                    target_type=target_type,
                    target_id=target_id,
                    label=label,
                    analyst_name=analyst_name,
                    notes=notes,
                    submitted_at=time.time(),
                )
                session.add(record)
        return feedback_id

    @staticmethod
    async def get_feedback_records() -> List[Dict[str, Any]]:
        """Retrieves all historical analyst feedback for model training."""
        async with AsyncSessionLocal() as session:
            stmt = select(AnalystFeedbackModel).order_by(desc(AnalystFeedbackModel.submitted_at))
            result = await session.execute(stmt)
            records = result.scalars().all()
            return [
                {
                    "id": r.id,
                    "target_type": r.target_type,
                    "target_id": r.target_id,
                    "label": r.label,
                    "analyst_name": r.analyst_name,
                    "notes": r.notes,
                    "submitted_at": r.submitted_at,
                }
                for r in records
            ]


    @staticmethod
    def save_alert_background(alert_dict: Dict[str, Any], agent_id: str = "local-agent") -> None:
        """Dispatches alert persistence to a background worker thread."""
        _db_executor.submit(
            lambda: asyncio.run(EDRRepository.save_alert(alert_dict, agent_id))
        )

    @staticmethod
    def save_scan_background(scan_dict: Dict[str, Any]) -> None:
        """Dispatches scan persistence to a background worker thread."""
        _db_executor.submit(
            lambda: asyncio.run(EDRRepository.save_scan(scan_dict))
        )

    @staticmethod
    def save_report_background(report_dict: Dict[str, Any], agent_id: str = "local-agent") -> None:
        """Dispatches report persistence to a background worker thread."""
        _db_executor.submit(
            lambda: asyncio.run(EDRRepository.save_incident_report(report_dict, agent_id))
        )


import concurrent.futures
_db_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="edr_db_worker")

# Singleton instance
edr_repo = EDRRepository()
