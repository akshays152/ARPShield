"""
Unit tests for Person 3's test scenarios -- validates scenario generation,
packet format (Person 1's schema), and expected metadata.

Does NOT import from detection/, prevention/, or ml/.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from testing.scenarios.normal_arp import NormalARPScenario
from testing.scenarios.ip_mac_conflict import IPMACConflictScenario
from testing.scenarios.gateway_spoofing import GatewaySpoofingScenario
from testing.scenarios.duplicate_ip import DuplicateIPScenario
from testing.scenarios.suspicious_replies import SuspiciousRepliesScenario
from testing.scenarios.high_arp_rate import HighARPRateScenario

# Person 1's schema keys
PERSON1_KEYS = {"timestamp", "sender_ip", "sender_mac",
                "target_ip", "target_mac", "operation"}

ALL_SCENARIO_CLASSES = [
    NormalARPScenario,
    IPMACConflictScenario,
    GatewaySpoofingScenario,
    DuplicateIPScenario,
    SuspiciousRepliesScenario,
    HighARPRateScenario,
]


class TestScenarioGeneration(unittest.TestCase):
    """Verify all scenarios produce valid ScenarioResult with packets
    in Person 1's schema.
    """

    def test_all_scenarios_generate_packets(self):
        for cls in ALL_SCENARIO_CLASSES:
            with self.subTest(scenario=cls.name):
                sr = cls().generate()
                self.assertGreater(len(sr.packets), 0,
                                   f"{cls.name} generated no packets")

    def test_all_packets_use_person1_schema(self):
        for cls in ALL_SCENARIO_CLASSES:
            with self.subTest(scenario=cls.name):
                sr = cls().generate()
                for pkt in sr.packets:
                    self.assertIsInstance(pkt, dict)
                    self.assertTrue(
                        PERSON1_KEYS.issubset(pkt.keys()),
                        f"Packet missing keys: {PERSON1_KEYS - pkt.keys()}"
                    )

    def test_all_packets_have_valid_operation(self):
        for cls in ALL_SCENARIO_CLASSES:
            with self.subTest(scenario=cls.name):
                sr = cls().generate()
                for pkt in sr.packets:
                    self.assertIn(pkt["operation"], ["request", "reply"])

    def test_scenario_result_metadata(self):
        for cls in ALL_SCENARIO_CLASSES:
            with self.subTest(scenario=cls.name):
                sr = cls().generate()
                self.assertIsInstance(sr.scenario_name, str)
                self.assertTrue(len(sr.scenario_name) > 0)
                self.assertIsInstance(sr.expected_detection, bool)
                self.assertIn(sr.expected_severity,
                              ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

    def test_normal_scenario_expects_no_detection(self):
        sr = NormalARPScenario().generate()
        self.assertFalse(sr.expected_detection)
        self.assertFalse(sr.is_attack)

    def test_attack_scenarios_expect_detection(self):
        attack_scenarios = [
            IPMACConflictScenario,
            GatewaySpoofingScenario,
            DuplicateIPScenario,
            SuspiciousRepliesScenario,
            HighARPRateScenario,
        ]
        for cls in attack_scenarios:
            with self.subTest(scenario=cls.name):
                sr = cls().generate()
                self.assertTrue(sr.expected_detection)
                self.assertTrue(sr.is_attack)

    def test_scenario_result_serialisation(self):
        """ScenarioResult.to_dict() should produce a dict."""
        for cls in ALL_SCENARIO_CLASSES:
            with self.subTest(scenario=cls.name):
                sr = cls().generate()
                d = sr.to_dict()
                self.assertIsInstance(d, dict)
                self.assertIn("scenario_name", d)
                self.assertIn("packets", d)

    def test_deterministic_with_same_seed(self):
        """Same seed should produce identical packets."""
        sr1 = NormalARPScenario().generate(seed=99)
        sr2 = NormalARPScenario().generate(seed=99)
        self.assertEqual(len(sr1.packets), len(sr2.packets))
        for p1, p2 in zip(sr1.packets, sr2.packets):
            self.assertEqual(p1["sender_ip"], p2["sender_ip"])
            self.assertEqual(p1["sender_mac"], p2["sender_mac"])

    def test_ip_mac_conflict_has_conflicting_macs(self):
        """IP-MAC conflict scenario should have multiple MACs for the
        same IP."""
        sr = IPMACConflictScenario().generate()
        ip_macs = {}
        for pkt in sr.packets:
            ip = pkt["sender_ip"]
            ip_macs.setdefault(ip, set()).add(pkt["sender_mac"])
        # At least one IP should have multiple MACs
        has_conflict = any(len(macs) > 1 for macs in ip_macs.values())
        self.assertTrue(has_conflict)

    def test_gateway_spoofing_targets_gateway_ip(self):
        """Gateway spoofing should have packets claiming to be the
        gateway with a non-gateway MAC."""
        sr = GatewaySpoofingScenario().generate()
        from testing.scenarios.base import GATEWAY_IP, GATEWAY_MAC
        gateway_macs = set()
        for pkt in sr.packets:
            if pkt["sender_ip"] == GATEWAY_IP:
                gateway_macs.add(pkt["sender_mac"])
        # Should have more than one MAC for the gateway IP
        self.assertGreater(len(gateway_macs), 1)

    def test_high_arp_rate_has_many_packets(self):
        """High ARP rate scenario should produce significantly more
        packets than the normal baseline."""
        sr = HighARPRateScenario().generate()
        self.assertGreater(len(sr.packets), 100)


if __name__ == "__main__":
    unittest.main()
