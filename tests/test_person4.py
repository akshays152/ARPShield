import tempfile
import unittest
from pathlib import Path

from prevention.risk_engine import assess_risk
from prevention.trusted_devices import TrustedDeviceStore
from prevention.response_workflow import ResponseWorkflow, ResponseStatus


class TestRiskEngine(unittest.TestCase):
    def test_low_risk(self):
        result = assess_risk({}, anomaly_score=0.10, is_anomaly=False)
        self.assertEqual(result.level, "LOW")

    def test_critical_when_both_engines_agree(self):
        result = assess_risk(
            {
                "mac_ip_change": True,
                "ip_mac_conflict": True,
                "unsolicited_reply": True,
            },
            anomaly_score=-0.6,
            is_anomaly=True,
        )
        self.assertEqual(result.level, "CRITICAL")
        self.assertGreaterEqual(result.score, 75)

    def test_trusted_device_is_not_a_bypass(self):
        result = assess_risk(
            {"gateway_mapping_change": True},
            anomaly_score=-0.5,
            is_anomaly=True,
            trusted_device=True,
        )
        self.assertGreater(result.score, 0)


class TestTrustedDevices(unittest.TestCase):
    def test_add_and_lookup(self):
        with tempfile.TemporaryDirectory() as td:
            store = TrustedDeviceStore(str(Path(td) / "trusted.json"))
            store.add("AA-BB-CC-DD-EE-FF", "192.168.1.10", "Laptop")
            self.assertTrue(store.is_trusted("aa:bb:cc:dd:ee:ff", "192.168.1.10"))
            self.assertFalse(store.is_trusted("aa:bb:cc:dd:ee:ff", "192.168.1.11"))


class TestResponseWorkflow(unittest.TestCase):
    def test_approval_is_required(self):
        with tempfile.TemporaryDirectory() as td:
            workflow = ResponseWorkflow(str(Path(td) / "responses.json"))
            workflow.create_request(
                "r1", "i1", "ISOLATE_DEVICE",
                {"mac": "aa:bb:cc:dd:ee:ff"},
                "High risk",
            )
            with self.assertRaises(PermissionError):
                workflow.execute("r1")

            workflow.approve("r1", "admin")
            result = workflow.execute("r1")
            self.assertEqual(result.status, ResponseStatus.EXECUTED)


if __name__ == "__main__":
    unittest.main()
