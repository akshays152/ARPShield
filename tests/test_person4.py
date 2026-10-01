import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from detection.src.detection_models import (
    DetectionResult,
    EventType,
    Severity,
)

from prevention.risk_engine import assess_risk
from prevention.service import RiskResponseService
from prevention.trusted_devices import TrustedDeviceStore
from prevention.response_workflow import (
    ResponseWorkflow,
    ResponseStatus,
)


class TestRiskEngine(unittest.TestCase):

    def test_low_risk(self):
        result = assess_risk({})

        self.assertEqual(
            result.level,
            "LOW",
        )

        self.assertEqual(
            result.score,
            0,
        )

    def test_critical_from_rule_findings(self):
        result = assess_risk(
            {
                "mac_ip_change": True,
                "ip_mac_conflict": True,
                "unsolicited_reply": True,
            }
        )

        self.assertEqual(
            result.level,
            "CRITICAL",
        )

        self.assertGreaterEqual(
            result.score,
            75,
        )

    def test_trusted_device_is_not_a_bypass(self):
        untrusted = assess_risk(
            {
                "gateway_mapping_change": True,
            }
        )

        trusted = assess_risk(
            {
                "gateway_mapping_change": True,
            },
            trusted_device=True,
        )

        self.assertEqual(
            untrusted.score,
            trusted.score,
        )

        self.assertEqual(
            trusted.level,
            "MEDIUM",
        )


class TestTrustedDevices(unittest.TestCase):

    def test_add_and_lookup(self):

        with tempfile.TemporaryDirectory() as td:

            store = TrustedDeviceStore(
                str(
                    Path(td) /
                    "trusted.json"
                )
            )

            store.add(
                "AA-BB-CC-DD-EE-FF",
                "192.168.1.10",
                "Laptop",
            )

            self.assertTrue(
                store.is_trusted(
                    "aa:bb:cc:dd:ee:ff",
                    "192.168.1.10",
                )
            )

            self.assertFalse(
                store.is_trusted(
                    "aa:bb:cc:dd:ee:ff",
                    "192.168.1.11",
                )
            )


class TestResponseWorkflow(unittest.TestCase):

    def test_approval_is_required(self):

        with tempfile.TemporaryDirectory() as td:

            workflow = ResponseWorkflow(
                str(
                    Path(td) /
                    "responses.json"
                )
            )

            workflow.create_request(
                "r1",
                "i1",
                "ISOLATE_DEVICE",
                {
                    "mac": (
                        "aa:bb:cc:dd:ee:ff"
                    )
                },
                "High risk",
            )

            with self.assertRaises(
                PermissionError
            ):
                workflow.execute("r1")

            workflow.approve(
                "r1",
                "admin",
            )

            result = workflow.execute(
                "r1"
            )

            self.assertEqual(
                result.status,
                ResponseStatus.EXECUTED,
            )


class TestDetectionIntegration(unittest.TestCase):

    def make_detection(
        self,
        severity: Severity,
    ) -> DetectionResult:

        return DetectionResult(
            detection_id="detect-test-1",

            event_type=(
                EventType.ARP_SPOOFING_ATTACK
            ),

            severity=severity,

            reason=(
                "Gateway IP claimed by "
                "an unexpected MAC"
            ),

            affected_device={
                "ip": "192.168.1.50",
                "mac": (
                    "aa:bb:cc:dd:ee:ff"
                ),
            },

            timestamp=datetime.now(
                timezone.utc
            ),
        )

    def test_high_detection_creates_isolation_request(self):

        with tempfile.TemporaryDirectory() as td:

            service = RiskResponseService(
                trusted_path=str(
                    Path(td) /
                    "trusted.json"
                ),

                incident_path=str(
                    Path(td) /
                    "incidents.jsonl"
                ),

                response_path=str(
                    Path(td) /
                    "responses.json"
                ),
            )

            result = service.process_detection(
                self.make_detection(
                    Severity.HIGH
                )
            )

            self.assertEqual(
                result["detection"]["severity"],
                "HIGH",
            )

            self.assertEqual(
                result["response_request"]["action"],
                "ISOLATE_DEVICE",
            )

            self.assertEqual(
                result["response_request"]["status"],
                "PENDING",
            )

    def test_medium_detection_marks_device_untrusted(self):

        with tempfile.TemporaryDirectory() as td:

            service = RiskResponseService(
                trusted_path=str(
                    Path(td) /
                    "trusted.json"
                ),

                incident_path=str(
                    Path(td) /
                    "incidents.jsonl"
                ),

                response_path=str(
                    Path(td) /
                    "responses.json"
                ),
            )

            result = service.process_detection(
                self.make_detection(
                    Severity.MEDIUM
                )
            )

            self.assertEqual(
                result["response_request"]["action"],
                "MARK_DEVICE_UNTRUSTED",
            )

    def test_low_detection_only_alerts(self):

        with tempfile.TemporaryDirectory() as td:

            service = RiskResponseService(
                trusted_path=str(
                    Path(td) /
                    "trusted.json"
                ),

                incident_path=str(
                    Path(td) /
                    "incidents.jsonl"
                ),

                response_path=str(
                    Path(td) /
                    "responses.json"
                ),
            )

            result = service.process_detection(
                self.make_detection(
                    Severity.LOW
                )
            )

            self.assertEqual(
                result["response_request"]["action"],
                "ALERT_ADMIN",
            )
class TestMitigationController(unittest.TestCase):

    def test_isolation_dry_run(self):
        from prevention.mitigation import MitigationController

        controller = MitigationController(
            dry_run=True
        )

        target = {
            "ip": "192.168.1.50",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

        result = controller.apply(
            "ISOLATE_DEVICE",
            target,
        )

        self.assertEqual(
            result.status,
            "COMPLETED",
        )

        self.assertTrue(
            result.reversible
        )

        self.assertTrue(
            controller.is_contained(target)
        )

    def test_recovery(self):
        from prevention.mitigation import MitigationController

        controller = MitigationController(
            dry_run=True
        )

        target = {
            "ip": "192.168.1.50",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

        controller.apply(
            "ISOLATE_DEVICE",
            target,
        )

        result = controller.recover(
            target
        )

        self.assertEqual(
            result.status,
            "RECOVERED",
        )

        self.assertFalse(
            controller.is_contained(target)
        )

    def test_invalid_action_is_rejected(self):
        from prevention.mitigation import MitigationController

        controller = MitigationController(
            dry_run=True
        )

        with self.assertRaises(
            ValueError
        ):
            controller.apply(
                "BLOCK_EVERYTHING",
                {
                    "ip": "192.168.1.50",
                    "mac": "aa:bb:cc:dd:ee:ff",
                },
            )

    def test_live_network_containment_is_disabled(self):
        from prevention.mitigation import MitigationController

        controller = MitigationController(
            dry_run=False
        )

        with self.assertRaises(
            RuntimeError
        ):
            controller.apply(
                "ISOLATE_DEVICE",
                {
                    "ip": "192.168.1.50",
                    "mac": "aa:bb:cc:dd:ee:ff",
                },
            )
class TestMitigationMonitoring(unittest.TestCase):

    def test_traffic_reduction_is_detected(self):
        from prevention.monitoring import MitigationMonitor

        monitor = MitigationMonitor(
            reduction_threshold=20.0
        )

        target = {
            "ip": "192.168.1.50",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

        result = monitor.evaluate(
            target=target,
            before_rate=100.0,
            after_rate=30.0,
        )

        self.assertEqual(
            result.status,
            "IMPROVED",
        )

        self.assertEqual(
            result.reduction_percent,
            70.0,
        )

    def test_insufficient_reduction_is_detected(self):
        from prevention.monitoring import MitigationMonitor

        monitor = MitigationMonitor(
            reduction_threshold=20.0
        )

        target = {
            "ip": "192.168.1.50",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

        result = monitor.evaluate(
            target=target,
            before_rate=100.0,
            after_rate=95.0,
        )

        self.assertEqual(
            result.status,
            "NOT_IMPROVED",
        )

        self.assertEqual(
            result.reduction_percent,
            5.0,
        )

    def test_negative_rate_is_rejected(self):
        from prevention.monitoring import MitigationMonitor

        monitor = MitigationMonitor()

        with self.assertRaises(
            ValueError
        ):
            monitor.evaluate(
                target={
                    "ip": "192.168.1.50",
                    "mac": "aa:bb:cc:dd:ee:ff",
                },
                before_rate=-10.0,
                after_rate=5.0,
            )
class TestMitigationIntegration(unittest.TestCase):

    def test_containment_monitoring_and_recovery(self):
        from prevention.mitigation import MitigationController

        controller = MitigationController(
            dry_run=True
        )

        target = {
            "ip": "192.168.1.50",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

        # Step 1: contain suspicious device
        mitigation = controller.apply(
            "ISOLATE_DEVICE",
            target,
        )

        self.assertEqual(
            mitigation.status,
            "COMPLETED",
        )

        self.assertTrue(
            controller.is_contained(target)
        )

        # Step 2: monitor traffic after mitigation
        monitoring = controller.monitor(
            target=target,
            before_rate=100.0,
            after_rate=25.0,
        )

        self.assertEqual(
            monitoring.status,
            "IMPROVED",
        )

        self.assertEqual(
            monitoring.reduction_percent,
            75.0,
        )

        # Step 3: recover the device
        recovery = controller.recover(
            target
        )

        self.assertEqual(
            recovery.status,
            "RECOVERED",
        )

        self.assertFalse(
            controller.is_contained(target)
        )
class TestImpactAnalyzer(unittest.TestCase):

    def test_impact_is_calculated(self):
        from prevention.impact import ImpactAnalyzer

        analyzer = ImpactAnalyzer()

        target = {
            "ip": "192.168.1.50",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

        result = analyzer.analyze(
            target=target,
            arp_rate_before=100.0,
            arp_rate_after=25.0,
            suspicious_rate_before=80.0,
            suspicious_rate_after=10.0,
            affected_hosts_before=4,
            affected_hosts_after=1,
            mitigation_time_seconds=8.5,
            recovery_verified=True,
        )

        self.assertEqual(
            result.arp_reduction_percent,
            75.0,
        )

        self.assertEqual(
            result.suspicious_reduction_percent,
            87.5,
        )

        self.assertEqual(
            result.affected_hosts_reduction,
            3,
        )

        self.assertEqual(
            result.mitigation_time_seconds,
            8.5,
        )

        self.assertTrue(
            result.recovery_verified
        )

    def test_negative_values_are_rejected(self):
        from prevention.impact import ImpactAnalyzer

        analyzer = ImpactAnalyzer()

        with self.assertRaises(ValueError):
            analyzer.analyze(
                target={
                    "ip": "192.168.1.50",
                    "mac": "aa:bb:cc:dd:ee:ff",
                },
                arp_rate_before=-1.0,
                arp_rate_after=10.0,
                suspicious_rate_before=10.0,
                suspicious_rate_after=2.0,
                affected_hosts_before=2,
                affected_hosts_after=0,
                mitigation_time_seconds=5.0,
                recovery_verified=True,
            )

if __name__ == "__main__":
    unittest.main()