"""
Active Process Mitigation Module.

Provides kernel-defensive process tree discovery, immediate execution suspension,
and cross-platform graceful termination with hard kill enforcement for targeted ransomware
processes and their descendants.
"""

from __future__ import annotations

import logging
import platform
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, List, Optional, Set

import psutil

# Configure structured audit logger for containment actions
logger = logging.getLogger("edr.mitigation")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [MITIGATION] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class MitigationAction(str, Enum):
    """Enumeration of containment actions executed against processes."""

    SUSPEND = "SUSPEND"
    TERMINATE = "TERMINATE"
    KILL = "KILL"
    ACCESS_DENIED = "ACCESS_DENIED"
    ALREADY_DEAD = "ALREADY_DEAD"


@dataclass
class ProcessNode:
    """Metadata representation of a target process in the discovered tree."""

    pid: int
    name: str
    cmdline: List[str]
    ppid: int
    status: str
    action_applied: MitigationAction = MitigationAction.SUSPEND


@dataclass
class MitigationResult:
    """Detailed audit record produced after an active mitigation event."""

    target_pid: int
    trigger_reason: str
    risk_score: float
    timestamp: float = field(default_factory=time.time)
    operating_system: str = field(default_factory=platform.platform)
    success: bool = False
    discovered_pids: List[int] = field(default_factory=list)
    terminated_pids: List[int] = field(default_factory=list)
    failed_pids: List[int] = field(default_factory=list)
    process_tree: List[ProcessNode] = field(default_factory=list)
    execution_time_ms: float = 0.0
    error_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert mitigation result into JSON-serializable dictionary."""
        return asdict(self)


class ProcessMitigator:
    """
    Enterprise-grade process tree containment engine.

    Executes a two-phase mitigation cycle:
    1. Freeze Phase: Instantly suspends the process tree to halt unauthorized encryption I/O.
    2. Containment Phase: Issues graceful SIGTERM, followed by SIGKILL for stubborn survivors.
    """

    def __init__(self, termination_timeout_sec: float = 3.0):
        """
        Initialize the process mitigator.

        Args:
            termination_timeout_sec: Maximum wait time before escalating from SIGTERM to SIGKILL.
        """
        self.termination_timeout_sec = termination_timeout_sec

    def discover_process_tree(self, root_pid: int) -> List[psutil.Process]:
        """
        Discovers the root process and all recursive child processes.

        Descendants are ordered bottom-up (children before parent) to prevent orphan spawning.
        """
        procs: List[psutil.Process] = []
        try:
            parent = psutil.Process(root_pid)
            children = parent.children(recursive=True)
            # Kill children first, then parent, to prevent runaway child spawning
            procs = children + [parent]
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            logger.warning("Root PID %d no longer exists during tree discovery.", root_pid)
        except psutil.AccessDenied:
            logger.error("Access denied discovering process tree for PID %d.", root_pid)
            # Try to at least retain the parent handle if possible
            try:
                procs = [psutil.Process(root_pid)]
            except Exception:
                pass
        return procs

    def suspend_process_tree(self, procs: List[psutil.Process]) -> Set[int]:
        """
        Suspends all threads in the process tree immediately.

        Halts disk encryption in user-space while termination is coordinated.
        """
        suspended_pids: Set[int] = set()
        for proc in procs:
            try:
                proc.suspend()
                suspended_pids.add(proc.pid)
                logger.info("Suspended thread scheduling for PID %d (%s).", proc.pid, proc.name())
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied:
                logger.warning("Access denied attempting to suspend PID %d.", proc.pid)
            except Exception as exc:
                logger.error("Unexpected error suspending PID %d: %s", proc.pid, exc)
        return suspended_pids

    def terminate_process_tree(
        self,
        target_pid: int,
        trigger_reason: str,
        risk_score: float,
    ) -> MitigationResult:
        """
        Actively neutralizes a malicious process tree.

        Steps:
        1. Discover entire process hierarchy.
        2. Freeze execution via SIGSTOP / NtSuspendProcess.
        3. Terminate via SIGTERM.
        4. Enforce SIGKILL / TerminateProcess on any process surviving the timeout.
        """
        start_time = time.perf_counter()
        result = MitigationResult(
            target_pid=target_pid,
            trigger_reason=trigger_reason,
            risk_score=risk_score,
        )

        try:
            procs = self.discover_process_tree(target_pid)
            if not procs:
                result.error_message = f"Process {target_pid} already dead or inaccessible."
                result.success = False
                result.execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
                return result

            result.discovered_pids = [p.pid for p in procs]

            # Build metadata snapshots before killing
            for p in procs:
                try:
                    cmdline = p.cmdline()
                    name = p.name()
                    ppid = p.ppid()
                    status = p.status()
                except Exception:
                    cmdline, name, ppid, status = [], "unknown", 0, "unknown"

                result.process_tree.append(
                    ProcessNode(
                        pid=p.pid,
                        name=name,
                        cmdline=cmdline,
                        ppid=ppid,
                        status=status,
                    )
                )

            # Phase 1: Freeze all processes immediately
            self.suspend_process_tree(procs)

            # Phase 2: Send graceful termination signal
            for proc in procs:
                try:
                    proc.terminate()
                    logger.info("Sent SIGTERM to PID %d (%s).", proc.pid, proc.name())
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    pass
                except psutil.AccessDenied:
                    logger.warning("Access denied sending SIGTERM to PID %d.", proc.pid)

            # Phase 3: Wait for exit
            gone, alive = psutil.wait_procs(procs, timeout=self.termination_timeout_sec)
            for p in gone:
                result.terminated_pids.append(p.pid)

            # Phase 4: Escalation to hard SIGKILL for survivors
            if alive:
                logger.warning(
                    "%d process(es) survived SIGTERM timeout. Escalating to SIGKILL.",
                    len(alive),
                )
                for proc in alive:
                    try:
                        proc.kill()
                        logger.warning("Sent SIGKILL / TerminateProcess to PID %d.", proc.pid)
                    except (psutil.NoSuchProcess, psutil.ZombieProcess):
                        result.terminated_pids.append(proc.pid)
                    except psutil.AccessDenied:
                        result.failed_pids.append(proc.pid)
                        logger.error("Access denied sending SIGKILL to PID %d!", proc.pid)

                # Final wait verification
                final_gone, final_alive = psutil.wait_procs(alive, timeout=1.0)
                for p in final_gone:
                    if p.pid not in result.terminated_pids:
                        result.terminated_pids.append(p.pid)
                for p in final_alive:
                    if p.pid not in result.failed_pids:
                        result.failed_pids.append(p.pid)

            result.success = target_pid in result.terminated_pids or not psutil.pid_exists(target_pid)

        except Exception as exc:
            logger.exception("Critical error during active mitigation of PID %d: %s", target_pid, exc)
            result.error_message = str(exc)
            result.success = False

        result.execution_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(
            "Mitigation concluded for PID %d. Success=%s. Terminated=%s. Failed=%s. Time=%.2fms",
            target_pid,
            result.success,
            result.terminated_pids,
            result.failed_pids,
            result.execution_time_ms,
        )
        return result


# Singleton instance for system-wide access
process_mitigator = ProcessMitigator()
