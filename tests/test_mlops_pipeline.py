import os
import sys
import unittest
from starlette.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.app import app
from backend.database import init_db


class MLOpsPipelineTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await init_db()
        self.client = TestClient(app)

    def test_01_submit_valid_analyst_feedback(self):
        payload = {
            "target_type": "alert",
            "target_id": "ALT-TEST-9999",
            "label": "true_positive",
            "analyst_name": "lead_soc_analyst",
            "notes": "Verified active LockBit 3.0 behavioral sequence.",
        }
        res = self.client.post("/api/ml/feedback", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["feedback_id"].startswith("FB-"))

    def test_02_submit_invalid_feedback_label(self):
        payload = {
            "target_type": "alert",
            "target_id": "ALT-TEST-9999",
            "label": "inconclusive",  # invalid enum
        }
        res = self.client.post("/api/ml/feedback", json=payload)
        self.assertEqual(res.status_code, 400)

    def test_03_list_feedback_records(self):
        res = self.client.get("/api/ml/feedback")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("feedback", data)
        self.assertGreaterEqual(data["count"], 1)

    def test_04_get_model_metadata(self):
        res = self.client.get("/api/ml/model/latest")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("model", data)
        model = data["model"]
        self.assertIn("version", model)
        self.assertIn("f1_score", model)
        self.assertIn("accuracy", model)

    def test_05_download_model_artifact(self):
        res = self.client.get("/api/ml/model/download")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/octet-stream", res.headers.get("content-type", ""))
        self.assertGreater(len(res.content), 1000)

    def test_06_retrain_and_live_promotion(self):
        res = self.client.post("/api/ml/retrain", json={"n_synthetic_samples": 400})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "promoted")
        meta = data["metadata"]
        self.assertTrue(meta["version"].startswith("v2."))
        self.assertGreaterEqual(meta["f1_score"], 0.90)
        self.assertGreaterEqual(meta["accuracy"], 0.90)
        self.assertIn("feature_importance", meta)
        self.assertIn("file_op_rate", meta["feature_importance"])


if __name__ == "__main__":
    unittest.main()
