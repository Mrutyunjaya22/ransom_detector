"""
Pre-Encryption IoC Command-Line Auditor.

Monitors process command-line arguments for precursor administrative sabotage techniques
routinely executed prior to ransomware encryption campaigns (e.g. shadow copy deletion,
bootloader modification, backup catalog destruction, and security log clearing).
Maps detections to MITRE ATT&CK Enterprise Matrix techniques.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import psutil

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.mitigation import ProcessMitigator, process_mitigator
from backend.repository import edr_repo
from backend.websocket_manager import ChannelType, ws_manager

logger = logging.getLogger("edr.ioc_auditor")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [IOC_AUDIT] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


@dataclass
class IoCRule:
    name: str
    pattern: re.Pattern
    mitre_attack_id: str
    mitre_attack_name: str
    severity: str
    description: str


# Comprehensive Pre-Encryption Ransomware Behavior Rules
IOC_RULES: List[IoCRule] = [
    IoCRule(
        name="VSS_SHADOW_COPY_DELETION",
        pattern=re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows(?:\s+/all)?(?:\s+/quiet)?", re.IGNORECASE),
        mitre_attack_id="T1490",
        mitre_attack_name="Inhibit System Recovery",
        severity="critical",
        description="Attempted destruction of Volume Shadow Copies using vssadmin to prevent file restoration.",
    ),
    IoCRule(
        name="WMIC_SHADOW_COPY_DELETION",
        pattern=re.compile(r"wmic(?:\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE),
        mitre_attack_id="T1490",
        mitre_attack_name="Inhibit System Recovery",
        severity="critical",
        description="WMI command invoking Win32_ShadowCopy deletion to cripple snapshot recovery.",
    ),
    IoCRule(
        name="POWERSHELL_SHADOW_COPY_PURGE",
        pattern=re.compile(r"(?:get-wmiobject|get-ciminstance).*(?:win32_shadowcopy|shadowstorage).*(?:delete|\.delete\(\)|remove-wmiobject)", re.IGNORECASE),
        mitre_attack_id="T1490",
        mitre_attack_name="Inhibit System Recovery",
        severity="critical",
        description="PowerShell scripted invocation to locate and delete all host backup shadow copies.",
    ),
    IoCRule(
        name="BCDEDIT_RECOVERY_DISABLE",
        pattern=re.compile(r"bcdedit(?:\.exe)?\s+.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", re.IGNORECASE),
        mitre_attack_id="T1490",
        mitre_attack_name="Inhibit System Recovery",
        severity="critical",
        description="Boot Configuration Data tampering disabling Windows automated startup repair and error recovery.",
    ),
    IoCRule(
        name="WBADMIN_BACKUP_PURGE",
        pattern=re.compile(r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)", re.IGNORECASE),
        mitre_attack_id="T1490",
        mitre_attack_name="Inhibit System Recovery",
        severity="critical",
        description="Windows Backup command purging backup catalog database to obstruct restoration.",
    ),
    IoCRule(
        name="SECURITY_LOG_CLEARING",
        pattern=re.compile(r"wevtutil(?:\.exe)?\s+(?:cl|clear-log)\s+(?:security|system|application)", re.IGNORECASE),
        mitre_attack_id="T1070.001",
        mitre_attack_name="Indicator Removal on Host: Clear Windows Event Logs",
        severity="high",
        description="Invocation of wevtutil to scrub forensic event logs prior to payload execution.",
    ),
    IoCRule(
        name="CRITICAL_SERVICE_KILL",
        pattern=re.compile(r"net(?:\.exe)?\s+stop\s+[\"']?(?:vss|sqlsrv|mssql|backup|veeam|acronis|sophos)[\"']?", re.IGNORECASE),
        mitre_attack_id="T1489",
        mitre_attack_name="Service Stop",
        severity="high",
        description="Terminating database and backup services to release open file locks for ransomware encryption.",
    ),
]


@dataclass
class IoCMatchResult:
    matched: bool
    rule: Optional[IoCRule] = None
    cmdline: str = ""
    pid: int = 0
    process_name: str = ""
    timestamp: float = 0.0

    def to_dict(self) -> Dict:
        if not self.matched or not self.rule:
            return {"matched": False}
        return {
            "matched": True,
            "rule_name": self.rule.name,
            "mitre_attack_id": self.rule.mitre_attack_id,
            "mitre_attack_name": self.rule.mitre_attack_name,
            "severity": self.rule.severity,
            "description": self.rule.description,
            "cmdline": self.cmdline,
            "pid": self.pid,
            "process_name": self.process_name,
            "timestamp": self.timestamp,
        }


class IoCAuditor:
    """
    Audits process executions and command-line vectors against pre-encryption IoCs.
    """

    def __init__(self, mitigator: Optional[ProcessMitigator] = None):
        self.mitigator = mitigator or process_mitigator
        self.rules = IOC_RULES

    def audit_command_string(
        self,
        cmdline: str,
        pid: int = 0,
        process_name: str = "unknown",
    ) -> IoCMatchResult:
        """Evaluates a raw command line string against all registered IoC patterns."""
        if not cmdline:
            return IoCMatchResult(matched=False)

        clean_cmd = cmdline.strip()
        for rule in self.rules:
            if rule.pattern.search(clean_cmd):
                logger.critical(
                    "PRE-ENCRYPTION IOC DETECTED: Rule='%s' MITRE=[%s: %s] PID=%d Cmd='%s'",
                    rule.name,
                    rule.mitre_attack_id,
                    rule.mitre_attack_name,
                    pid,
                    clean_cmd,
                )
                return IoCMatchResult(
                    matched=True,
                    rule=rule,
                    cmdline=clean_cmd,
                    pid=pid,
                    process_name=process_name,
                    timestamp=time.time(),
                )
        return IoCMatchResult(matched=False)

    def scan_active_processes(self, auto_mitigate: bool = True) -> List[IoCMatchResult]:
        """
        Enumerates all active processes on the host system and audits their launch arguments.
        If an IoC is identified and auto_mitigate is True, immediately neutralizes the process.
        """
        detections: List[IoCMatchResult] = []
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmd_list = proc.info.get("cmdline") or []
                if not cmd_list:
                    continue
                cmd_str = " ".join(cmd_list)
                pid = proc.info["pid"]
                name = proc.info.get("name") or "unknown"

                result = self.audit_command_string(cmd_str, pid=pid, process_name=name)
                if result.matched and result.rule:
                    detections.append(result)

                    # Broadcast alert
                    alert_payload = {
                        "id": f"ALT-IOC-{int(time.time())}-{pid}",
                        "severity": result.rule.severity,
                        "process": name,
                        "pid": pid,
                        "score": 0.98 if result.rule.severity == "critical" else 0.85,
                        "reasons": [
                            f"MITRE {result.rule.mitre_attack_id} ({result.rule.mitre_attack_name}): {result.rule.description}"
                        ],
                        "affected_paths": [],
                        "createdAt": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "timestamp": time.time(),
                    }
                    ws_manager.broadcast_sync(ChannelType.ALERTS, "alert_raised", alert_payload)
                    edr_repo.save_alert_background(alert_payload)

                    # Trigger mitigation
                    if auto_mitigate and pid > 0:
                        self.mitigator.terminate_process_tree(
                            target_pid=pid,
                            trigger_reason=f"Pre-encryption IoC: {result.rule.name} ({result.rule.mitre_attack_id})",
                            risk_score=0.98,
                        )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return detections


# Global singleton instance
ioc_auditor = IoCAuditor()
