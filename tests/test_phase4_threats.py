import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.canary import CanaryTrapManager
from core.ioc_auditor import IoCAuditor, IOC_RULES


class Phase4ThreatsTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="edr_canary_test_")
        self.canary_mgr = CanaryTrapManager(base_dir=self.temp_dir)
        self.ioc_auditor = IoCAuditor()

    def tearDown(self):
        self.canary_mgr.cleanup()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_canary_deployment_and_integrity(self):
        deployed = self.canary_mgr.deploy_canaries()
        self.assertGreaterEqual(len(deployed), 4)

        # All canaries should initially be intact
        tampered_initial = self.canary_mgr.check_all_canaries()
        self.assertEqual(len(tampered_initial), 0)

        for path in deployed:
            self.assertTrue(self.canary_mgr.check_integrity(path))

    def test_canary_tamper_detection(self):
        deployed = self.canary_mgr.deploy_canaries()
        target_canary = deployed[0]

        # Simulate ransomware encrypting/modifying the canary
        with open(target_canary, "wb") as f:
            f.write(b"ENCRYPTED_RANSOMWARE_PAYLOAD_CORRUPT_BYTES")

        tampered = self.canary_mgr.check_all_canaries(default_pid=9999)
        self.assertEqual(len(tampered), 1)
        record = tampered[0]
        self.assertEqual(record.path, target_canary)
        self.assertTrue(record.is_tampered)
        self.assertEqual(record.tamper_event, "content_modified_or_encrypted")
        self.assertEqual(record.tampering_pid, 9999)

    def test_canary_deletion_detection(self):
        deployed = self.canary_mgr.deploy_canaries()
        target_canary = deployed[1]

        # Simulate ransomware deleting the original file after writing .locked
        os.remove(target_canary)

        tampered = self.canary_mgr.check_all_canaries(default_pid=8888)
        self.assertEqual(len(tampered), 1)
        record = tampered[0]
        self.assertEqual(record.path, target_canary)
        self.assertEqual(record.tamper_event, "deleted_or_renamed")

    def test_ioc_shadow_copy_deletion(self):
        cmd = "vssadmin.exe delete shadows /all /quiet"
        res = self.ioc_auditor.audit_command_string(cmd, pid=5555, process_name="vssadmin.exe")
        self.assertTrue(res.matched)
        self.assertEqual(res.rule.name, "VSS_SHADOW_COPY_DELETION")
        self.assertEqual(res.rule.mitre_attack_id, "T1490")
        self.assertEqual(res.rule.severity, "critical")

    def test_ioc_bcdedit_recovery_disable(self):
        cmd = "bcdedit /set {default} recoveryenabled No"
        res = self.ioc_auditor.audit_command_string(cmd, pid=5556, process_name="bcdedit.exe")
        self.assertTrue(res.matched)
        self.assertEqual(res.rule.name, "BCDEDIT_RECOVERY_DISABLE")
        self.assertEqual(res.rule.mitre_attack_id, "T1490")

    def test_ioc_wbadmin_backup_purge(self):
        cmd = "wbadmin delete catalog -quiet"
        res = self.ioc_auditor.audit_command_string(cmd, pid=5557, process_name="wbadmin.exe")
        self.assertTrue(res.matched)
        self.assertEqual(res.rule.name, "WBADMIN_BACKUP_PURGE")
        self.assertEqual(res.rule.mitre_attack_id, "T1490")

    def test_ioc_security_log_clearing(self):
        cmd = "wevtutil.exe cl Security"
        res = self.ioc_auditor.audit_command_string(cmd, pid=5558, process_name="wevtutil.exe")
        self.assertTrue(res.matched)
        self.assertEqual(res.rule.name, "SECURITY_LOG_CLEARING")
        self.assertEqual(res.rule.mitre_attack_id, "T1070.001")

    def test_ioc_critical_service_kill(self):
        cmd = "net stop \"vss\""
        res = self.ioc_auditor.audit_command_string(cmd, pid=5559, process_name="net.exe")
        self.assertTrue(res.matched)
        self.assertEqual(res.rule.name, "CRITICAL_SERVICE_KILL")
        self.assertEqual(res.rule.mitre_attack_id, "T1489")

    def test_benign_command_not_flagged(self):
        benign_commands = [
            "python.exe app.py --port 8000",
            "git commit -m 'feat: update ransomware detector'",
            "node.exe server.js",
            "curl https://api.example.com/v1/health",
        ]
        for cmd in benign_commands:
            res = self.ioc_auditor.audit_command_string(cmd)
            self.assertFalse(res.matched, f"Benign command '{cmd}' was erroneously flagged!")


if __name__ == "__main__":
    unittest.main()
