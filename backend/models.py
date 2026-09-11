"""
Relational Database Models for EDR State & Persistence.

Defines schemas for registered endpoints, telemetry streams, alerts,
forensic incident reports, file scans, and analyst triage feedback.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from backend.database import Base


class AgentModel(Base):
    """Represents an active EDR endpoint client reporting telemetry."""

    __tablename__ = "agents"

    agent_id = Column(String(64), primary_key=True, index=True)
    hostname = Column(String(128), nullable=False)
    ip_address = Column(String(45), nullable=False)
    os_platform = Column(String(128), nullable=False)
    status = Column(String(32), default="online", index=True)  # online, offline, isolated
    last_heartbeat = Column(Float, default=time.time, index=True)
    registered_at = Column(Float, default=time.time)

    # Relationships
    alerts = relationship("AlertModel", back_populates="agent", cascade="all, delete-orphan")
    reports = relationship("IncidentReportModel", back_populates="agent", cascade="all, delete-orphan")


class TelemetryEventModel(Base):
    """Archival store for raw filesystem and process telemetry events."""

    __tablename__ = "telemetry_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(64), index=True, default="local-agent")
    ts = Column(Float, nullable=False, index=True)
    kind = Column(String(32), nullable=False, index=True)  # fs_create, fs_modify, etc.
    pid = Column(Integer, nullable=True, index=True)
    path = Column(String(512), nullable=True)
    dest_path = Column(String(512), nullable=True)
    extra_data = Column(JSON, default=dict)


class AlertModel(Base):
    """Security alert emitted when behavioral risk crosses detection thresholds."""

    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, index=True)
    agent_id = Column(String(64), ForeignKey("agents.agent_id"), nullable=True, index=True)
    timestamp = Column(Float, nullable=False, index=True)
    pid = Column(Integer, nullable=False, index=True)
    process = Column(String(128), nullable=False)
    score = Column(Float, nullable=False, index=True)
    rule_score = Column(Float, default=0.0)
    ml_score = Column(Float, default=0.0)
    severity = Column(String(16), nullable=False, index=True)  # low, medium, high, critical
    reasons = Column(JSON, default=list)
    affected_paths = Column(JSON, default=list)
    recommended_action = Column(String(256), default="isolate/kill process and quarantine affected paths")
    createdAt = Column(String(64), nullable=False)

    agent = relationship("AgentModel", back_populates="alerts")


class IncidentReportModel(Base):
    """Forensic incident reconstruction report detailing a validated ransomware campaign."""

    __tablename__ = "incident_reports"

    id = Column(String(64), primary_key=True, index=True)
    agent_id = Column(String(64), ForeignKey("agents.agent_id"), nullable=True, index=True)
    mode = Column(String(32), default="attack")
    verdict = Column(String(32), nullable=False, index=True)  # clean, suspicious, malicious
    peak_score = Column(Float, nullable=False, index=True)
    alert_count = Column(Integer, default=0)
    created_at = Column(String(64), nullable=False)
    process = Column(String(128), nullable=False)
    pid = Column(Integer, nullable=False)
    duration_sec = Column(Integer, default=30)
    features = Column(JSON, default=dict)
    timeline = Column(JSON, default=list)
    recommendation = Column(Text, default="")
    summary = Column(Text, default="")

    agent = relationship("AgentModel", back_populates="reports")


class ScanModel(Base):
    """Triage scan records for artifacts evaluated through the streaming file scanner."""

    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, index=True)
    file_name = Column(String(256), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    entropy = Column(Float, nullable=False)
    score = Column(Float, nullable=False, index=True)
    verdict = Column(String(32), nullable=False, index=True)  # clean, suspicious, malicious
    reasons = Column(JSON, default=list)
    features = Column(JSON, default=dict)
    scanned_at = Column(String(64), nullable=False)


class AnalystFeedbackModel(Base):
    """SOC analyst feedback labels for active model retraining and telemetry validation."""

    __tablename__ = "analyst_feedback"

    id = Column(String(64), primary_key=True, index=True)
    target_type = Column(String(32), nullable=False, index=True)  # alert, incident, scan
    target_id = Column(String(64), nullable=False, index=True)
    label = Column(String(32), nullable=False, index=True)  # true_positive, false_positive
    analyst_name = Column(String(64), default="analyst")
    notes = Column(Text, default="")
    submitted_at = Column(Float, default=time.time)
