import time
import unittest

from backend.pipeline_service import PipelineService


class PipelineServiceTests(unittest.TestCase):
    def test_status_payload_exposes_live_multi_stage_analysis(self):
        service = PipelineService()
        service.mode = "attack"
        service.stage = "scoring"
        service._run_started_at = time.time()
        service._record_observation(
            {
                "risk_score": 0.82,
                "rule_score": 0.74,
                "ml_score": 0.9,
                "features": {
                    "file_op_rate": 6.2,
                    "mean_entropy": 7.8,
                    "high_entropy_fraction": 0.8,
                    "ext_change_rate": 2.1,
                    "suspicious_ext_rate": 0.4,
                    "cpu_percent": 84.0,
                    "children_spawned": 4,
                    "io_bytes_per_s": 320000.0,
                    "touched_file_count": 19,
                },
                "reasons": ["entropy jump + mass file writes in window"],
                "ts": time.time(),
            }
        )

        payload = service.status_payload()

        self.assertIn("analysis", payload)
        self.assertEqual(payload["analysis"]["currentStage"], "scoring")
        self.assertGreaterEqual(len(payload["analysis"]["activeStages"]), 5)
        self.assertGreaterEqual(len(payload["analysis"]["evidence"]), 1)
        self.assertGreaterEqual(payload["analysis"]["summary"]["riskScore"], 0.0)


if __name__ == "__main__":
    unittest.main()
