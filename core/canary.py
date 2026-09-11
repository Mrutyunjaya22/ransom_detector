"""
Canary Bait File Trap Module.

Deploys cryptographically hashed decoy files in sensitive user and system directories.
Any modification, renaming, truncation, or deletion of a canary instantly trips a tripwire alert,
attributes the tampering process, and invokes active mitigation containment.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.mitigation import ProcessMitigator, process_mitigator

logger = logging.getLogger("edr.canary")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [CANARY] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

CANARY_NAMES = [
    "!00_passwords_vault.xlsx",
    "!00_confidential_financials.docx",
    "!00_crypto_wallet_backup.dat",
    "00_master_security_keys.pdf",
]


@dataclass
class CanaryRecord:
    path: str
    original_sha256: str
    size_bytes: int
    created_at: float
    is_tampered: bool = False
    tampered_at: Optional[float] = None
    tamper_event: Optional[str] = None
    tampering_pid: Optional[int] = None


class CanaryTrapManager:
    """
    Manages bait file deployment, continuous integrity checks,
    and instantaneous tripwire containment.
    """

    def __init__(
        self,
        base_dir: Optional[str] = None,
        mitigator: Optional[ProcessMitigator] = None,
        on_tamper_callback: Optional[Callable[[CanaryRecord], None]] = None,
    ):
        self.base_dir = base_dir or os.path.join(ROOT, "test_sandbox")
        self.mitigator = mitigator or process_mitigator
        self.on_tamper_callback = on_tamper_callback
        self.canaries: Dict[str, CanaryRecord] = {}

    @staticmethod
    def _compute_hash(path: str) -> Optional[str]:
        """Calculates SHA-256 hash of a file."""
        if not os.path.exists(path):
            return None
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, PermissionError):
            return None

    def deploy_canaries(self, target_dir: Optional[str] = None) -> List[str]:
        """
        Deploys canary files with pseudo-decoy content into the target directory.
        Names are prefixed with '!00_' to ensure ransomware encrypts them first in alphabetical order.
        """
        deploy_dir = target_dir or self.base_dir
        os.makedirs(deploy_dir, exist_ok=True)
        deployed_paths = []

        for name in CANARY_NAMES:
            file_path = os.path.join(deploy_dir, name)
            # Create synthetic high-value decoy content with known entropy
            content = f"--- ENTERPRISE CONFIDENTIAL DATA RECORD {name} ---\n".encode("utf-8")
            content += os.urandom(2048)  # 2KB random seed

            with open(file_path, "wb") as f:
                f.write(content)

            sha256_hash = hashlib.sha256(content).hexdigest()
            record = CanaryRecord(
                path=os.path.abspath(file_path),
                original_sha256=sha256_hash,
                size_bytes=len(content),
                created_at=time.time(),
            )
            self.canaries[record.path] = record
            deployed_paths.append(record.path)

        logger.info("Successfully deployed %d canary bait files to '%s'", len(deployed_paths), deploy_dir)
        return deployed_paths

    def check_integrity(self, file_path: str, triggering_pid: Optional[int] = None) -> bool:
        """
        Validates the cryptographic integrity of a canary file.
        Returns True if intact, False if tampered or missing.
        """
        abs_path = os.path.abspath(file_path)
        if abs_path not in self.canaries:
            return True  # Not a registered canary

        record = self.canaries[abs_path]
        if record.is_tampered:
            return False  # Already tripped

        # Check existence
        if not os.path.exists(abs_path):
            self._handle_tamper(record, "deleted_or_renamed", triggering_pid)
            return False

        # Check content hash
        current_hash = self._compute_hash(abs_path)
        if current_hash != record.original_sha256:
            self._handle_tamper(record, "content_modified_or_encrypted", triggering_pid)
            return False

        return True

    def check_all_canaries(self, default_pid: Optional[int] = None) -> List[CanaryRecord]:
        """Audits all deployed canaries and returns a list of tampered records."""
        tampered = []
        for path in list(self.canaries.keys()):
            if not self.check_integrity(path, triggering_pid=default_pid):
                tampered.append(self.canaries[path])
        return tampered

    def _handle_tamper(self, record: CanaryRecord, event_type: str, pid: Optional[int]) -> None:
        """Executes instant defensive countermeasures when a canary is disturbed."""
        record.is_tampered = True
        record.tampered_at = time.time()
        record.tamper_event = event_type
        record.tampering_pid = pid

        logger.critical(
            "TRIPWIRE ACTIVATED! Canary bait file tampered: '%s' Event='%s' PID=%s",
            record.path,
            event_type,
            str(pid) if pid else "unknown",
        )

        # Autonomous active containment
        if pid and pid > 0:
            logger.warning("Initiating immediate emergency containment on tampering PID %d", pid)
            try:
                mitigation_res = self.mitigator.terminate_process_tree(
                    target_pid=pid,
                    trigger_reason=f"Canary bait file tripwire triggered on {os.path.basename(record.path)} ({event_type})",
                    risk_score=1.0,
                )
                logger.info("Tripwire mitigation result: %s", mitigation_res.to_dict())
            except Exception as exc:
                logger.error("Failed to mitigate PID %d: %s", pid, exc)

        # Broadcast or invoke callback
        if self.on_tamper_callback:
            try:
                self.on_tamper_callback(record)
            except Exception as exc:
                logger.error("Error in tamper callback: %s", exc)

    def cleanup(self) -> None:
        """Removes all deployed canary files upon sandbox teardown."""
        for path in list(self.canaries.keys()):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass
        self.canaries.clear()
        logger.info("Canary bait files cleaned up.")


# Global singleton
canary_manager = CanaryTrapManager()
