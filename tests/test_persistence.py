import asyncio
import os
import sys
import time
import unittest
from starlette.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.app import app
from backend.database import init_db
from backend.repository import edr_repo


class PersistenceTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await init_db()
        self.client = TestClient(app)

    async def test_agent_registration_and_update(self):
        agent = await edr_repo.register_agent(
            agent_id="agt-test-001",
            hostname="DESKTOP-SEC-01",
            ip_address="192.168.1.105",
            os_platform="Windows 11 Pro",
        )
        self.assertEqual(agent.agent_id, "agt-test-001")
        self.assertEqual(agent.hostname, "DESKTOP-SEC-01")
        self.assertEqual(agent.status, "online")

    async def test_alert_persistence_and_query(self):
        alert_dict = {
            "id": f"ALT-TEST-{int(time.time())}",
            "timestamp": time.time(),
            "pid": 9999,
            "process": "crypto_locker.exe",
            "score": 0.96,
            "rule_score": 0.90,
            "ml_score": 0.98,
            "severity": "critical",
            "reasons": ["Entropy spike 7.91", "Mass renaming to .locked"],
            "affected_paths": ["C:\\Data\\doc.locked"],
            "recommended_action": "terminate process",
            "createdAt": "2026-09-11 21:00:00",
        }
        await edr_repo.save_alert(alert_dict, agent_id="agt-test-001")
        alerts = await edr_repo.get_alerts(limit=10)
        self.assertGreaterEqual(len(alerts), 1)
        found = any(a["id"] == alert_dict["id"] for a in alerts)
        self.assertTrue(found)

    async def test_incident_report_persistence(self):
        report_id = f"IR-TEST-{int(time.time())}"
        report_dict = {
            "id": report_id,
            "mode": "attack",
            "verdict": "malicious",
            "peakScore": 0.92,
            "alertCount": 3,
            "createdAt": "2026-09-11 21:10:00",
            "process": "ransomware_test.exe",
            "pid": 4321,
            "durationSec": 30,
            "features": {"mean_entropy": 7.8, "touched_file_count": 45},
            "timeline": [{"t": 1.2, "score": 0.92, "event": "bulk encryption"}],
            "recommendation": "quarantine host",
            "summary": "Ransomware test incident",
        }
        await edr_repo.save_incident_report(report_dict, agent_id="agt-test-001")
        reports = await edr_repo.get_reports(limit=10)
        self.assertTrue(any(r["id"] == report_id for r in reports))

        detail = await edr_repo.get_report_by_id(report_id)
        self.assertIsNotNone(detail)
        self.assertEqual(detail["id"], report_id)
        self.assertEqual(detail["verdict"], "malicious")
        self.assertEqual(detail["pid"], 4321)

    async def test_scan_persistence(self):
        scan_id = f"SCN-TEST-{int(time.time())}"
        scan_dict = {
            "id": scan_id,
            "fileName": "suspicious_payload.bin",
            "sizeBytes": 2048,
            "entropy": 7.85,
            "score": 0.91,
            "verdict": "malicious",
            "reasons": ["High Shannon entropy"],
            "features": {"detectedMimeOrMagic": "PE Binary"},
            "scannedAt": "2026-09-11 21:15:00",
        }
        await edr_repo.save_scan(scan_dict)
        scans = await edr_repo.get_scans(limit=10)
        self.assertTrue(any(s["id"] == scan_id for s in scans))

    async def test_analyst_feedback_loop(self):
        fb_id = await edr_repo.save_analyst_feedback(
            target_type="alert",
            target_id="ALT-001",
            label="true_positive",
            analyst_name="alice_soc",
            notes="Confirmed ransomware detonation activity",
        )
        self.assertTrue(fb_id.startswith("FB-"))
        records = await edr_repo.get_feedback_records()
        self.assertTrue(any(r["id"] == fb_id for r in records))

    def test_app_endpoints_integration(self):
        # Register agent via API
        reg_res = self.client.post(
            "/api/agents/register",
            json={
                "agent_id": "agt-api-002",
                "hostname": "ENDPOINT-DEV-02",
                "ip_address": "10.0.0.42",
                "os_platform": "Windows 10 Enterprise",
            },
        )
        self.assertEqual(reg_res.status_code, 200)
        self.assertEqual(reg_res.json()["agent_id"], "agt-api-002")

        # Query alerts endpoint
        alerts_res = self.client.get("/api/alerts")
        self.assertEqual(alerts_res.status_code, 200)
        self.assertIn("alerts", alerts_res.json())

        # Query reports endpoint
        reports_res = self.client.get("/api/reports")
        self.assertEqual(reports_res.status_code, 200)
        self.assertIn("reports", reports_res.json())

        # Query scans endpoint
        scans_res = self.client.get("/api/scans")
        self.assertEqual(scans_res.status_code, 200)
        self.assertIn("scans", scans_res.json())


if __name__ == "__main__":
    unittest.main()
