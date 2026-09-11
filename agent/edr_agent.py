"""
Decoupled Standalone EDR Endpoint Agent.

Monitors local filesystem mutations and process telemetry, streams batched telemetry
to the central SOC over gRPC, and executes autonomous local process mitigation upon receiving
mitigation directives from the behavioral engine.
"""

from __future__ import annotations

import argparse
import logging
import math
import os
import platform
import queue
import socket
import sys
import threading
import time
import uuid
from typing import Iterator, List, Optional

import grpc
import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.mitigation import ProcessMitigator, process_mitigator
from core.features import ExtensionTracker
import proto.edr_telemetry_pb2 as pb
import proto.edr_telemetry_pb2_grpc as pb_grpc

logger = logging.getLogger("edr.agent")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [AGENT] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def compute_fast_entropy(file_path: str, max_bytes: int = 65536) -> float:
    """Computes Shannon entropy over the first 64KB of a file."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        n = float(len(data))
        ent = 0.0
        for c in counts:
            if c > 0:
                p = c / n
                ent -= p * math.log2(p)
        return round(ent, 3)
    except Exception:
        return 0.0


class AgentFSHandler(FileSystemEventHandler):
    """Captures filesystem events and feeds the agent batching queue."""

    def __init__(self, event_queue: queue.Queue):
        super().__init__()
        self.queue = event_queue

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._push_event(pb.FileEvent.CREATE, event.src_path)

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._push_event(pb.FileEvent.MODIFY, event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            self._push_event(pb.FileEvent.DELETE, event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self._push_event(pb.FileEvent.MOVE, event.src_path, getattr(event, "dest_path", ""))

    def _push_event(self, event_type: int, src_path: str, dest_path: str = ""):
        _, ext = os.path.splitext((dest_path or src_path).lower())
        is_suspicious = ext in ExtensionTracker.SUSPICIOUS_EXTENSIONS or ".locked" in src_path.lower()
        ent = compute_fast_entropy(src_path) if event_type != pb.FileEvent.DELETE and os.path.exists(src_path) else 0.0

        fe = pb.FileEvent(
            event_type=event_type,
            path=src_path,
            dest_path=dest_path,
            timestamp=time.time(),
            entropy=ent,
            is_suspicious_ext=is_suspicious,
            process_id=0,  # Correlated on server side or kernel probe
        )
        self.queue.put(fe)


class EDRAgent:
    """
    Autonomous EDR Endpoint Sensor Client.
    """

    def __init__(
        self,
        server_address: str = "127.0.0.1:50051",
        watch_dir: Optional[str] = None,
        agent_id: Optional[str] = None,
        mitigator: Optional[ProcessMitigator] = None,
    ):
        self.server_address = server_address
        self.watch_dir = watch_dir or os.path.join(ROOT, "test_sandbox")
        self.agent_id = agent_id or f"agt-{socket.gethostname().lower()}-{uuid.uuid4().hex[:6]}"
        self.mitigator = mitigator or process_mitigator
        self.channel: Optional[grpc.Channel] = None
        self.stub: Optional[pb_grpc.EDRTelemetryServiceStub] = None
        self.session_token: Optional[str] = None
        self.running = False

        self.file_event_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.observer: Optional[Observer] = None
        self.heartbeat_thread: Optional[threading.Thread] = None

    def connect(self) -> bool:
        """Establishes gRPC channel and registers endpoint with server."""
        try:
            self.channel = grpc.insecure_channel(
                self.server_address,
                options=[
                    ("grpc.max_receive_message_length", 32 * 1024 * 1024),
                    ("grpc.max_send_message_length", 32 * 1024 * 1024),
                ],
            )
            self.stub = pb_grpc.EDRTelemetryServiceStub(self.channel)

            ip = socket.gethostbyname(socket.gethostname())
            info = pb.AgentInfo(
                agent_id=self.agent_id,
                hostname=socket.gethostname(),
                ip_address=ip,
                os_platform=f"{platform.system()} {platform.release()}",
                agent_version="2.0.0",
            )
            resp = self.stub.RegisterAgent(info, timeout=5.0)
            if resp.status == "approved":
                self.session_token = resp.session_token
                logger.info(
                    "Agent '%s' successfully registered with EDR server %s",
                    self.agent_id,
                    self.server_address,
                )
                return True
            else:
                logger.error("Agent registration rejected by server: %s", resp.status)
                return False
        except Exception as exc:
            logger.error("Failed to connect/register with EDR server: %s", exc)
            return False

    def start_filesystem_monitor(self):
        """Starts watchdog observer on target directory."""
        if not os.path.exists(self.watch_dir):
            os.makedirs(self.watch_dir, exist_ok=True)
        handler = AgentFSHandler(self.file_event_queue)
        self.observer = Observer()
        self.observer.schedule(handler, self.watch_dir, recursive=True)
        self.observer.start()
        logger.info("Filesystem monitoring active on directory: %s", self.watch_dir)

    def _heartbeat_loop(self, interval_sec: float = 15.0):
        """Periodically reports agent liveness and resource usage."""
        while self.running and self.stub:
            try:
                hb = pb.Heartbeat(
                    agent_id=self.agent_id,
                    timestamp=time.time(),
                    cpu_usage_percent=float(psutil.cpu_percent()),
                    memory_usage_percent=float(psutil.virtual_memory().percent),
                    monitored_processes_count=len(psutil.pids()),
                )
                self.stub.SendHeartbeat(hb, timeout=3.0)
            except Exception as exc:
                logger.debug("Heartbeat transmission error: %s", exc)
            time.sleep(interval_sec)

    def generate_telemetry_batches(self) -> Iterator[pb.TelemetryBatch]:
        """Generator that yields TelemetryBatch objects to the server stream."""
        batch_seq = 0
        while self.running:
            file_events: List[pb.FileEvent] = []
            while len(file_events) < 50:
                try:
                    fe = self.file_event_queue.get_nowait()
                    file_events.append(fe)
                except queue.Empty:
                    break

            # Collect process snapshots for active processes
            proc_metrics: List[pb.ProcessMetric] = []
            if file_events:
                for proc in psutil.process_iter(["pid", "name", "cpu_percent", "num_threads"]):
                    try:
                        pinfo = proc.info
                        pm = pb.ProcessMetric(
                            pid=pinfo["pid"],
                            process_name=pinfo.get("name") or "",
                            cmdline="",
                            cpu_percent=float(pinfo.get("cpu_percent") or 0.0),
                            io_bytes_per_s=0.0,
                            threads_count=int(pinfo.get("num_threads") or 0),
                            children_count=len(proc.children()),
                            timestamp=time.time(),
                        )
                        proc_metrics.append(pm)
                        if len(proc_metrics) >= 10:
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

            if file_events or proc_metrics:
                batch_seq += 1
                batch = pb.TelemetryBatch(
                    agent_id=self.agent_id,
                    batch_id=f"B-{self.agent_id}-{batch_seq}",
                    timestamp=time.time(),
                    file_events=file_events,
                    process_metrics=proc_metrics,
                )
                yield batch

            time.sleep(0.5)

    def execute_directive(self, directive: pb.MitigationDirective):
        """Executes active containment against a malicious process."""
        logger.warning(
            "MITIGATION DIRECTIVE RECEIVED: Action=%s PID=%d Reason='%s' Risk=%.2f",
            pb.MitigationDirective.ActionType.Name(directive.action),
            directive.target_pid,
            directive.reason,
            directive.risk_score,
        )
        if directive.target_pid and directive.action in (
            pb.MitigationDirective.TERMINATE,
            pb.MitigationDirective.KILL,
            pb.MitigationDirective.SUSPEND,
        ):
            res = self.mitigator.terminate_process_tree(
                target_pid=directive.target_pid,
                trigger_reason=directive.reason,
                risk_score=directive.risk_score,
            )
            logger.info("Mitigation execution result: %s", res.to_dict())

    def run(self):
        """Starts the agent sensor and streaming loop."""
        self.running = True
        if not self.connect():
            logger.error("Could not start agent: Connection failed.")
            return

        self.start_filesystem_monitor()

        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

        try:
            # Bidirectional streaming RPC call
            directives_stream = self.stub.StreamTelemetry(self.generate_telemetry_batches())
            for directive in directives_stream:
                self.execute_directive(directive)
        except grpc.RpcError as rpc_err:
            logger.warning("Stream ended or server disconnected: %s", rpc_err)
        except Exception as exc:
            logger.error("Agent run loop encountered error: %s", exc)
        finally:
            self.stop()

    def stop(self):
        """Shuts down all agent sensor components gracefully."""
        self.running = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2.0)
            except Exception:
                pass
        if self.channel:
            self.channel.close()
        logger.info("EDR Agent '%s' halted.", self.agent_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EDR Endpoint Sensor Agent")
    parser.add_argument("--server", default="127.0.0.1:50051", help="gRPC Server address")
    parser.add_argument("--watch", default=os.path.join(ROOT, "test_sandbox"), help="Watch directory")
    parser.add_argument("--id", default=None, help="Agent unique identifier")
    args = parser.parse_args()

    agent = EDRAgent(server_address=args.server, watch_dir=args.watch, agent_id=args.id)
    agent.run()
