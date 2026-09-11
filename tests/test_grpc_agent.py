import os
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import grpc
from backend.grpc_server import create_grpc_server
import proto.edr_telemetry_pb2 as pb
import proto.edr_telemetry_pb2_grpc as pb_grpc


class GRPCAgentTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_port = 50055
        cls.server = create_grpc_server(host="127.0.0.1", port=cls.test_port)
        cls.server.start()
        time.sleep(0.5)
        cls.channel = grpc.insecure_channel(f"127.0.0.1:{cls.test_port}")
        cls.stub = pb_grpc.EDRTelemetryServiceStub(cls.channel)

    @classmethod
    def tearDownClass(cls):
        cls.channel.close()
        cls.server.stop(grace=0.5)

    def test_01_agent_registration(self):
        info = pb.AgentInfo(
            agent_id="agt-unit-test-01",
            hostname="TEST-WORKSTATION",
            ip_address="192.168.1.99",
            os_platform="Windows 11",
            agent_version="2.0.0",
        )
        resp = self.stub.RegisterAgent(info, timeout=3.0)
        self.assertEqual(resp.status, "approved")
        self.assertEqual(resp.assigned_id, "agt-unit-test-01")
        self.assertTrue(resp.session_token.startswith("tok_"))
        self.assertEqual(resp.heartbeat_interval_sec, 15)

    def test_02_heartbeat_exchange(self):
        hb = pb.Heartbeat(
            agent_id="agt-unit-test-01",
            timestamp=time.time(),
            cpu_usage_percent=12.5,
            memory_usage_percent=45.2,
            monitored_processes_count=120,
        )
        ack = self.stub.SendHeartbeat(hb, timeout=3.0)
        self.assertTrue(ack.acknowledged)
        self.assertGreater(ack.server_timestamp, 0)

    def test_03_telemetry_streaming_and_mitigation_trigger(self):
        # We simulate a malicious ransomware burst of high entropy files under PID 8888
        target_pid = 8888
        file_events = []
        for i in range(40):
            file_events.append(
                pb.FileEvent(
                    event_type=pb.FileEvent.MOVE,
                    path=f"C:\\Sandbox\\document_{i}.docx",
                    dest_path=f"C:\\Sandbox\\document_{i}.docx.locked",
                    timestamp=time.time(),
                    entropy=7.95,
                    is_suspicious_ext=True,
                    process_id=target_pid,
                )
            )

        proc_metrics = [
            pb.ProcessMetric(
                pid=target_pid,
                process_name="ransom_payload.exe",
                cmdline="C:\\ransom_payload.exe -encrypt",
                cpu_percent=85.0,
                io_bytes_per_s=500000.0,
                threads_count=8,
                children_count=0,
                timestamp=time.time(),
            )
        ]

        batch = pb.TelemetryBatch(
            agent_id="agt-unit-test-01",
            batch_id="batch-attack-001",
            timestamp=time.time(),
            file_events=file_events,
            process_metrics=proc_metrics,
        )

        def batch_generator():
            yield batch

        directives_stream = self.stub.StreamTelemetry(batch_generator(), timeout=5.0)
        directives = list(directives_stream)

        # Server should evaluate the attack pattern and yield at least one MitigationDirective
        self.assertGreaterEqual(len(directives), 1)
        directive = directives[0]
        self.assertEqual(directive.target_pid, target_pid)
        self.assertEqual(directive.action, pb.MitigationDirective.TERMINATE)
        self.assertGreaterEqual(directive.risk_score, 0.85)
        self.assertTrue(len(directive.reason) > 0)


if __name__ == "__main__":
    unittest.main()
