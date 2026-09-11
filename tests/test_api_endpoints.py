import io
import os
import unittest
from starlette.testclient import TestClient

from backend.app import app
from backend.pipeline_service import pipeline_service


class ApiEndpointsTestCase(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_status_endpoint(self):
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("pipeline", data)
        self.assertIn("stage", data["pipeline"])
        self.assertIn("modelLoaded", data)
        self.assertIn("analysis", data)
        self.assertIn("activeStages", data["analysis"])

    def test_alerts_endpoint_schema(self):
        # Add a mock alert via pipeline_service
        class MockAlert:
            ts = 1789140000.0
            pid = 12345
            risk_score = 0.88
            rule_score = 0.85
            ml_score = 0.91
            reasons = ["entropy jump + mass file writes in window"]
            affected_paths = ["test.docx.locked"]

        formatted = pipeline_service._make_alert(MockAlert())
        pipeline_service.alerts.insert(0, formatted)

        res = self.client.get("/api/alerts")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("alerts", data)
        self.assertGreaterEqual(len(data["alerts"]), 1)

        first = data["alerts"][0]
        self.assertIn("id", first)
        self.assertIn("severity", first)
        self.assertEqual(first["severity"], "critical")
        self.assertIn("process", first)
        self.assertIn("pid", first)
        self.assertIn("score", first)
        self.assertIsInstance(first["score"], float)
        self.assertIn("createdAt", first)

    def test_reports_and_report_detail_schema(self):
        res = self.client.get("/api/reports")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("reports", data)

        if data["reports"]:
            rep_id = data["reports"][0]["id"]
            detail_res = self.client.get(f"/api/reports/{rep_id}")
            self.assertEqual(detail_res.status_code, 200)
            rep = detail_res.json()["report"]
            self.assertIn("id", rep)
            self.assertIn("verdict", rep)
            self.assertIn("peakScore", rep)
            self.assertIsInstance(rep["peakScore"], float)
            self.assertIn("durationSec", rep)
            self.assertIn("features", rep)
            self.assertIsInstance(rep["features"], dict)
            self.assertIn("timeline", rep)
            self.assertIsInstance(rep["timeline"], list)
            self.assertIn("alerts", rep)
            self.assertIsInstance(rep["alerts"], list)
            self.assertIn("recommendation", rep)

    def test_scan_benign_file(self):
        content = b"This is a benign quarterly report with regular english words. " * 50
        file_obj = io.BytesIO(content)
        res = self.client.post(
            "/api/scan",
            files={"file": ("quarterly_report.txt", file_obj, "text/plain")},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("scan", data)
        scan = data["scan"]
        self.assertEqual(scan["fileName"], "quarterly_report.txt")
        self.assertLess(scan["entropy"], 6.0)
        self.assertEqual(scan["verdict"], "clean")
        self.assertLess(scan["score"], 0.4)

    def test_scan_ransomware_file(self):
        # 4096 bytes of random encrypted data with a locked extension
        encrypted_content = os.urandom(4096)
        file_obj = io.BytesIO(encrypted_content)
        res = self.client.post(
            "/api/scan",
            files={"file": ("financial_records.docx.locked", file_obj, "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("scan", data)
        scan = data["scan"]
        self.assertEqual(scan["fileName"], "financial_records.docx.locked")
        self.assertGreaterEqual(scan["entropy"], 7.5)
        self.assertEqual(scan["verdict"], "malicious")
        self.assertGreaterEqual(scan["score"], 0.6)

    def test_get_scans_history(self):
        # Post a scan first to ensure history is populated
        content = b"sample scan test file"
        self.client.post("/api/scan", files={"file": ("sample.txt", io.BytesIO(content), "text/plain")})
        res = self.client.get("/api/scan")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("scans", data)
        self.assertIsInstance(data["scans"], list)
        self.assertGreaterEqual(len(data["scans"]), 1)

    def test_run_validation(self):
        res = self.client.post("/api/run", json={"mode": "invalid_mode"})
        self.assertEqual(res.status_code, 400)


if __name__ == "__main__":
    unittest.main()
