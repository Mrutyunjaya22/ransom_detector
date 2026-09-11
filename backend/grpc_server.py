"""
gRPC Telemetry Ingestion & Real-Time Mitigation Server.

Implements high-throughput binary RPC protocol for decoupled remote endpoint sensors,
sub-second behavioral analysis via BehavioralEngine, and bidirectional mitigation directive streaming.
"""

from __future__ import annotations

import asyncio
from concurrent import futures
import logging
import os
import sys
import time
import uuid
from typing import AsyncIterator, Dict, Iterator, Optional

import grpc

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.collector import Event
from core.engine import BehavioralEngine
from backend.repository import edr_repo
from backend.websocket_manager import ChannelType, ws_manager
import proto.edr_telemetry_pb2 as pb
import proto.edr_telemetry_pb2_grpc as pb_grpc

logger = logging.getLogger("edr.grpc")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [gRPC] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

MODEL_PATH = os.path.join(ROOT, "models", "rf_classifier.pkl")


class EDRTelemetryServicer(pb_grpc.EDRTelemetryServiceServicer):
    """
    gRPC Servicer handling remote endpoint telemetry ingestion,
    heartbeat validation, and containment commands.
    """

    def __init__(self, engine: Optional[BehavioralEngine] = None):
        self.engine = engine or BehavioralEngine(MODEL_PATH)
        self.active_agents: Dict[str, Dict] = {}

    def RegisterAgent(
        self,
        request: pb.AgentInfo,
        context: grpc.ServicerContext,
    ) -> pb.RegistrationResponse:
        """Handles initial endpoint sensor registration."""
        logger.info(
            "Registration request from Agent '%s' (%s, %s, OS: %s, v%s)",
            request.agent_id,
            request.hostname,
            request.ip_address,
            request.os_platform,
            request.agent_version,
        )

        session_token = f"tok_{uuid.uuid4().hex}"
        self.active_agents[request.agent_id] = {
            "hostname": request.hostname,
            "ip_address": request.ip_address,
            "os_platform": request.os_platform,
            "last_seen": time.time(),
            "token": session_token,
        }

        # Persist to database asynchronously
        try:
            import asyncio
            asyncio.run(
                edr_repo.register_agent(
                    agent_id=request.agent_id,
                    hostname=request.hostname,
                    ip_address=request.ip_address,
                    os_platform=request.os_platform,
                )
            )
        except Exception as exc:
            logger.warning("Could not persist agent to DB: %s", exc)

        return pb.RegistrationResponse(
            status="approved",
            assigned_id=request.agent_id,
            session_token=session_token,
            heartbeat_interval_sec=15,
        )

    def SendHeartbeat(
        self,
        request: pb.Heartbeat,
        context: grpc.ServicerContext,
    ) -> pb.HeartbeatAck:
        """Processes agent heartbeat status and resource utilization."""
        if request.agent_id in self.active_agents:
            self.active_agents[request.agent_id]["last_seen"] = time.time()

        return pb.HeartbeatAck(
            acknowledged=True,
            server_timestamp=time.time(),
        )

    def StreamTelemetry(
        self,
        request_iterator: Iterator[pb.TelemetryBatch],
        context: grpc.ServicerContext,
    ) -> Iterator[pb.MitigationDirective]:
        """
        Bidirectional stream: Consumes TelemetryBatch objects from agent,
        feeds the behavioral model, and streams back MitigationDirective if risk is critical.
        """
        logger.info("Agent telemetry stream established.")
        try:
            for batch in request_iterator:
                agent_id = batch.agent_id
                # Ingest file events
                for fe in batch.file_events:
                    event_kind_map = {
                        pb.FileEvent.CREATE: "fs_create",
                        pb.FileEvent.MODIFY: "fs_modify",
                        pb.FileEvent.DELETE: "fs_delete",
                        pb.FileEvent.MOVE: "fs_rename",
                    }
                    kind = event_kind_map.get(fe.event_type, "fs_modify")
                    entropy_val = fe.entropy if fe.entropy > 0 else (7.8 if fe.is_suspicious_ext else 3.5)

                    raw_event = Event(
                        ts=fe.timestamp or time.time(),
                        kind=kind,
                        pid=fe.process_id,
                        path=fe.path,
                        dest_path=fe.dest_path or (fe.path if kind == "fs_rename" else None),
                        extra={"entropy": entropy_val},
                    )
                    self.engine.ingest(raw_event)

                # Ingest process metrics
                for pm in batch.process_metrics:
                    proc_event = Event(
                        ts=pm.timestamp or time.time(),
                        kind="proc_snapshot",
                        pid=pm.pid,
                        path=None,
                        dest_path=None,
                        extra={
                            "cpu_percent": pm.cpu_percent,
                            "io_bytes_per_s": pm.io_bytes_per_s,
                            "num_threads": pm.threads_count,
                            "num_children": pm.children_count,
                            "cmdline": pm.cmdline,
                        },
                    )
                    self.engine.ingest(proc_event)

                # Evaluate risk for all reported processes
                evaluated_pids = set(fe.process_id for fe in batch.file_events if fe.process_id)
                evaluated_pids.update(pm.pid for pm in batch.process_metrics if pm.pid)

                for pid in evaluated_pids:
                    eval_result = self.engine.risk_score(pid)
                    risk_score = eval_result["risk_score"]
                    reasons = eval_result.get("reasons", [])

                    # Broadcast telemetry evaluation to SOC UI
                    ws_manager.broadcast_sync(
                        ChannelType.TELEMETRY,
                        "telemetry_evaluated",
                        {
                            "agent_id": agent_id,
                            "pid": pid,
                            "risk_score": risk_score,
                            "reasons": reasons,
                            "timestamp": time.time(),
                        },
                    )

                    # Containment Trigger: Risk >= 0.80
                    if risk_score >= 0.80:
                        reason_str = "; ".join(reasons) or "Anomalous high entropy file modifications detected"
                        logger.warning(
                            "CRITICAL THREAT on Agent '%s' PID %d (Score: %.2f)! Emitting mitigation directive.",
                            agent_id,
                            pid,
                            risk_score,
                        )

                        # Emit alert to dashboard & DB
                        alert_id = f"ALT-GRPC-{int(time.time())}-{pid}"
                        alert_payload = {
                            "id": alert_id,
                            "severity": "critical",
                            "process": f"pid_{pid}",
                            "pid": pid,
                            "score": round(risk_score, 3),
                            "rule_score": round(eval_result.get("rule_score", 0.0), 3),
                            "ml_score": round(eval_result.get("ml_score", 0.0), 3),
                            "reasons": reasons,
                            "createdAt": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "timestamp": time.time(),
                        }
                        ws_manager.broadcast_sync(ChannelType.ALERTS, "alert_raised", alert_payload)
                        edr_repo.save_alert_background(alert_payload, agent_id=agent_id)

                        # Stream directive back to endpoint sensor for immediate containment
                        directive = pb.MitigationDirective(
                            directive_id=f"DIR-{uuid.uuid4().hex[:8]}",
                            target_pid=pid,
                            action=pb.MitigationDirective.TERMINATE,
                            reason=reason_str,
                            risk_score=float(risk_score),
                            timestamp=time.time(),
                        )
                        yield directive

        except Exception as exc:
            logger.error("Telemetry stream interrupted: %s", exc)


def create_grpc_server(
    host: str = "0.0.0.0",
    port: int = 50051,
    max_workers: int = 10,
    engine: Optional[BehavioralEngine] = None,
) -> grpc.Server:
    """Instantiates and registers the EDR gRPC Telemetry Server."""
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        options=[
            ("grpc.max_receive_message_length", 32 * 1024 * 1024),
            ("grpc.max_send_message_length", 32 * 1024 * 1024),
        ],
    )
    servicer = EDRTelemetryServicer(engine=engine)
    pb_grpc.add_EDRTelemetryServiceServicer_to_server(servicer, server)
    server.add_insecure_port(f"{host}:{port}")
    return server


if __name__ == "__main__":
    server = create_grpc_server(host="127.0.0.1", port=50051)
    server.start()
    logger.info("EDR gRPC Telemetry Server listening on 127.0.0.1:50051")
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(grace=1.0)
