import asyncio
import io
import subprocess
import sys
import time
import unittest
from starlette.testclient import TestClient

from backend.app import app
from backend.mitigation import ProcessMitigator, process_mitigator
from backend.scan_router import StreamingEntropyCalculator, MAX_ALLOWED_FILE_SIZE
from backend.websocket_manager import ChannelType, ws_manager


class Phase1HardeningTestCase(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_streaming_entropy_calculator_chunking(self):
        """Validates that online 256-bin histogram produces correct Shannon entropy across chunks."""
        calc = StreamingEntropyCalculator()
        sample_chunk1 = b"AAAA" * 100
        sample_chunk2 = b"BBBB" * 100

        calc.update(sample_chunk1)
        calc.update(sample_chunk2)

        entropy = calc.compute_entropy()
        # Exactly 2 symbols equally distributed -> -2 * (0.5 * log2(0.5)) = 1.000 bits/byte
        self.assertAlmostEqual(entropy, 1.000, places=2)
        self.assertEqual(calc.total_bytes, 800)

    def test_magic_byte_header_recognition(self):
        """Verifies magic byte detection across known binary and archive headers."""
        tests = [
            (b"MZ\x90\x00\x03\x00", "Windows PE Executable / DLL"),
            (b"\x7fELF\x02\x01\x01\x00", "Linux ELF Binary"),
            (b"PK\x03\x04\x14\x00", "ZIP / OpenXML Archive (.docx/.xlsx/.jar)"),
            (b"%PDF-1.7\r\n", "Adobe Portable Document Format (PDF)"),
            (b"\x1f\x8b\x08\x00", "GZIP Compressed Archive"),
            (b"7z\xbc\xaf\x27\x1c", "7-Zip Compressed Archive"),
            (b"plain text bytes without magic", "Generic Binary / Data Stream"),
        ]
        for header, expected_label in tests:
            calc = StreamingEntropyCalculator()
            calc.update(header)
            self.assertEqual(calc.detect_magic_type(), expected_label)

    def test_active_process_mitigation(self):
        """Spawns a real subprocess and tests suspend -> terminate -> kill containment cycle."""
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(15)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pid = proc.pid
        time.sleep(0.2)

        # Verify process is actively running
        self.assertIsNone(proc.poll())

        # Execute active mitigation
        mitigator = ProcessMitigator(termination_timeout_sec=1.5)
        result = mitigator.terminate_process_tree(
            target_pid=pid,
            trigger_reason="Test Ransomware Simulation Containment",
            risk_score=0.95,
        )

        self.assertTrue(result.success)
        self.assertIn(pid, result.terminated_pids)
        self.assertEqual(len(result.failed_pids), 0)
        self.assertGreater(result.execution_time_ms, 0)

        # Confirm process has indeed exited
        self.assertIsNotNone(proc.poll())

    def test_websocket_manager_broadcast(self):
        """Validates WebSocket connection manager registration and sync broadcast dispatching."""
        # Test sync broadcast dispatching does not raise exception
        ws_manager.broadcast_sync(
            ChannelType.ALERTS,
            "test_alert",
            {"status": "test", "score": 0.99},
        )

    def test_scan_router_streaming_endpoint(self):
        """Validates that chunked streaming upload works through the mounted scan_router."""
        payload = b"Streaming upload test payload line " * 50
        res = self.client.post(
            "/api/scan",
            files={"file": ("streaming_test.txt", io.BytesIO(payload), "text/plain")},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()["scan"]
        self.assertEqual(data["fileName"], "streaming_test.txt")
        self.assertIn("detectedMimeOrMagic", data["features"])
        self.assertIn("sizeBytes", data["features"])


if __name__ == "__main__":
    unittest.main()
