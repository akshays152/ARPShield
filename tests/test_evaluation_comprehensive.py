"""
Comprehensive unit tests for Person 3's testing module.

Covers:
  - Detection metric calculation (including accuracy)
  - Zero-division edge cases
  - Detection latency calculation
  - False-positive analysis
  - DDoS impact analysis (analyze_ddos_impact, compare_mitigation_phases)
  - Disruption indicator calculation
  - Normal and suspicious scenario generation
  - Report generation (JSON, CSV, TXT, Markdown)
  - Detection adapter behavior (StubDetector, DetectionEvent, MitigationResult)
  - Visualization module availability check

Does NOT import from detection/, prevention/, or ml/.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from testing.evaluation.detection_metrics import (
    compute_confusion_values,
    compute_detection_metrics,
)
from testing.evaluation.detection_time import compute_detection_time_metrics
from testing.evaluation.false_positive_analysis import analyze_false_positives
from testing.evaluation.ddos_impact import (
    analyze_traffic_profile,
    compare_conditions,
    analyze_ddos_impact,
    compare_mitigation_phases,
    compute_disruption_indicator,
    build_ddos_impact_report,
)
from testing.evaluation.report_generator import generate_report
from testing.integration.detection_adapter import (
    DetectionAdapter, DetectionEvent, StubDetector, MitigationResult,
)

from testing.scenarios.normal_arp import NormalARPScenario
from testing.scenarios.ip_mac_conflict import IPMACConflictScenario
from testing.scenarios.gateway_spoofing import GatewaySpoofingScenario
from testing.scenarios.duplicate_ip import DuplicateIPScenario
from testing.scenarios.suspicious_replies import SuspiciousRepliesScenario
from testing.scenarios.high_arp_rate import HighARPRateScenario


# ═══════════════════════════════════════════════════════════════════════
# DETECTION METRICS
# ═══════════════════════════════════════════════════════════════════════


class TestConfusionValues(unittest.TestCase):

    def test_true_positive(self):
        self.assertEqual(compute_confusion_values(True, True), "TP")

    def test_true_negative(self):
        self.assertEqual(compute_confusion_values(False, False), "TN")

    def test_false_positive(self):
        self.assertEqual(compute_confusion_values(False, True), "FP")

    def test_false_negative(self):
        self.assertEqual(compute_confusion_values(True, False), "FN")


class TestDetectionMetrics(unittest.TestCase):

    def test_perfect_detection(self):
        results = [
            {"expected_detection": True, "actual_detected": True},
            {"expected_detection": True, "actual_detected": True},
            {"expected_detection": False, "actual_detected": False},
        ]
        m = compute_detection_metrics(results)
        self.assertEqual(m["true_positives"], 2)
        self.assertEqual(m["true_negatives"], 1)
        self.assertEqual(m["false_positives"], 0)
        self.assertEqual(m["false_negatives"], 0)
        self.assertAlmostEqual(m["accuracy"], 1.0)
        self.assertAlmostEqual(m["detection_rate"], 1.0)
        self.assertAlmostEqual(m["precision"], 1.0)
        self.assertAlmostEqual(m["recall"], 1.0)
        self.assertAlmostEqual(m["f1_score"], 1.0)
        self.assertAlmostEqual(m["false_positive_rate"], 0.0)

    def test_all_false_negatives(self):
        results = [
            {"expected_detection": True, "actual_detected": False},
            {"expected_detection": True, "actual_detected": False},
        ]
        m = compute_detection_metrics(results)
        self.assertEqual(m["true_positives"], 0)
        self.assertEqual(m["false_negatives"], 2)
        self.assertAlmostEqual(m["accuracy"], 0.0)
        self.assertAlmostEqual(m["detection_rate"], 0.0)
        self.assertAlmostEqual(m["recall"], 0.0)

    def test_mixed_results(self):
        results = [
            {"expected_detection": True, "actual_detected": True},     # TP
            {"expected_detection": True, "actual_detected": False},    # FN
            {"expected_detection": False, "actual_detected": False},   # TN
            {"expected_detection": False, "actual_detected": True},    # FP
        ]
        m = compute_detection_metrics(results)
        self.assertEqual(m["true_positives"], 1)
        self.assertEqual(m["true_negatives"], 1)
        self.assertEqual(m["false_positives"], 1)
        self.assertEqual(m["false_negatives"], 1)
        self.assertAlmostEqual(m["accuracy"], 0.5)
        self.assertAlmostEqual(m["detection_rate"], 0.5)
        self.assertAlmostEqual(m["false_positive_rate"], 0.5)
        self.assertAlmostEqual(m["precision"], 0.5)

    def test_empty_results(self):
        """Zero-division safety: empty input should not raise."""
        m = compute_detection_metrics([])
        self.assertEqual(m["total_scenarios"], 0)
        self.assertEqual(m["true_positives"], 0)
        self.assertAlmostEqual(m["accuracy"], 0.0)
        self.assertAlmostEqual(m["f1_score"], 0.0)

    def test_all_true_negatives(self):
        """Only normal traffic, all correctly ignored."""
        results = [
            {"expected_detection": False, "actual_detected": False},
            {"expected_detection": False, "actual_detected": False},
        ]
        m = compute_detection_metrics(results)
        self.assertAlmostEqual(m["accuracy"], 1.0)
        self.assertEqual(m["true_negatives"], 2)
        self.assertAlmostEqual(m["false_positive_rate"], 0.0)

    def test_accuracy_present(self):
        """Accuracy field must always be present."""
        results = [{"expected_detection": True, "actual_detected": True}]
        m = compute_detection_metrics(results)
        self.assertIn("accuracy", m)


# ═══════════════════════════════════════════════════════════════════════
# DETECTION TIMING
# ═══════════════════════════════════════════════════════════════════════


class TestDetectionTimeMetrics(unittest.TestCase):

    def test_basic_timing(self):
        results = [
            {"actual_detected": True, "detection_latency_ms": 10.0},
            {"actual_detected": True, "detection_latency_ms": 20.0},
            {"actual_detected": True, "detection_latency_ms": 30.0},
        ]
        t = compute_detection_time_metrics(results)
        self.assertEqual(t["samples"], 3)
        self.assertAlmostEqual(t["average_detection_time_ms"], 20.0)
        self.assertAlmostEqual(t["min_detection_time_ms"], 10.0)
        self.assertAlmostEqual(t["max_detection_time_ms"], 30.0)

    def test_no_detections(self):
        results = [
            {"actual_detected": False, "detection_latency_ms": None},
        ]
        t = compute_detection_time_metrics(results)
        self.assertEqual(t["samples"], 0)
        self.assertIsNone(t["average_detection_time_ms"])
        self.assertIsNone(t["min_detection_time_ms"])
        self.assertIsNone(t["max_detection_time_ms"])
        self.assertIsNone(t["median_detection_time_ms"])

    def test_single_detection(self):
        results = [
            {"actual_detected": True, "detection_latency_ms": 42.5},
        ]
        t = compute_detection_time_metrics(results)
        self.assertEqual(t["samples"], 1)
        self.assertAlmostEqual(t["average_detection_time_ms"], 42.5)
        self.assertAlmostEqual(t["stddev_detection_time_ms"], 0.0)

    def test_empty_results(self):
        """Zero-division safety for empty input."""
        t = compute_detection_time_metrics([])
        self.assertEqual(t["samples"], 0)
        self.assertIsNone(t["average_detection_time_ms"])

    def test_mixed_detected_and_not(self):
        """Only detected scenarios with latency should count."""
        results = [
            {"actual_detected": True, "detection_latency_ms": 5.0},
            {"actual_detected": False, "detection_latency_ms": None},
            {"actual_detected": True, "detection_latency_ms": 15.0},
        ]
        t = compute_detection_time_metrics(results)
        self.assertEqual(t["samples"], 2)
        self.assertAlmostEqual(t["average_detection_time_ms"], 10.0)


# ═══════════════════════════════════════════════════════════════════════
# FALSE POSITIVE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════


class TestFalsePositiveAnalysis(unittest.TestCase):

    def test_no_errors(self):
        results = [
            {
                "scenario_name": "normal",
                "expected_detection": False,
                "actual_detected": False,
                "detection_events": [],
                "expected_event_types": [],
            },
            {
                "scenario_name": "attack",
                "expected_detection": True,
                "actual_detected": True,
                "detection_events": [{"event_type": "IP_MAC_MAPPING_CHANGE", "severity": "MEDIUM", "reason": "test"}],
                "expected_event_types": ["IP_MAC_MAPPING_CHANGE"],
            },
        ]
        fp = analyze_false_positives(results)
        self.assertEqual(fp["total_false_positives"], 0)
        self.assertEqual(fp["total_false_negatives"], 0)

    def test_false_positive_counted(self):
        results = [
            {
                "scenario_name": "normal_but_detected",
                "expected_detection": False,
                "actual_detected": True,
                "detection_events": [{"event_type": "UNUSUAL_ARP_ACTIVITY", "severity": "HIGH", "reason": "test fp"}],
                "expected_event_types": [],
            },
        ]
        fp = analyze_false_positives(results)
        self.assertEqual(fp["total_false_positives"], 1)
        self.assertIn("UNUSUAL_ARP_ACTIVITY", fp["false_positives_by_rule"])

    def test_false_negative_counted(self):
        results = [
            {
                "scenario_name": "attack_missed",
                "expected_detection": True,
                "actual_detected": False,
                "detection_events": [],
                "expected_event_types": ["GATEWAY_MAPPING_CHANGE"],
            },
        ]
        fp = analyze_false_positives(results)
        self.assertEqual(fp["total_false_negatives"], 1)
        self.assertIn("GATEWAY_MAPPING_CHANGE", fp["false_negatives_by_expected_type"])

    def test_empty_results(self):
        """Empty input should not raise."""
        fp = analyze_false_positives([])
        self.assertEqual(fp["total_false_positives"], 0)
        self.assertEqual(fp["total_false_negatives"], 0)

    def test_multiple_fp_by_rule(self):
        """Multiple FP events should be counted per rule."""
        results = [
            {
                "scenario_name": "fp1",
                "expected_detection": False,
                "actual_detected": True,
                "detection_events": [
                    {"event_type": "RULE_A", "severity": "LOW", "reason": "x"},
                    {"event_type": "RULE_A", "severity": "LOW", "reason": "y"},
                ],
                "expected_event_types": [],
            },
        ]
        fp = analyze_false_positives(results)
        self.assertEqual(fp["false_positives_by_rule"]["RULE_A"], 2)


# ═══════════════════════════════════════════════════════════════════════
# DDoS IMPACT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════


class TestTrafficProfile(unittest.TestCase):

    def test_analyze_traffic_profile(self):
        packets = [
            {"timestamp": "2026-01-01T00:00:00", "operation": "request",
             "sender_ip": "10.0.0.1", "sender_mac": "aa:bb:cc:dd:ee:01",
             "target_ip": "10.0.0.2", "target_mac": "ff:ff:ff:ff:ff:ff"},
            {"timestamp": "2026-01-01T00:00:01", "operation": "reply",
             "sender_ip": "10.0.0.2", "sender_mac": "aa:bb:cc:dd:ee:02",
             "target_ip": "10.0.0.1", "target_mac": "aa:bb:cc:dd:ee:01"},
        ]
        profile = analyze_traffic_profile(packets, "test")
        self.assertEqual(profile["total_packets"], 2)
        self.assertEqual(profile["requests"], 1)
        self.assertEqual(profile["replies"], 1)
        self.assertEqual(profile["unique_source_ips"], 2)

    def test_empty_packets(self):
        profile = analyze_traffic_profile([], "empty")
        self.assertEqual(profile["total_packets"], 0)
        self.assertEqual(profile["packets_per_second"], 0.0)

    def test_compare_conditions(self):
        normal = {"total_packets": 10, "packets_per_second": 1.0,
                  "conflicting_ip_mac_mappings": 0, "unique_source_macs": 3,
                  "requests": 5, "replies": 5}
        abnormal = {"total_packets": 100, "packets_per_second": 50.0,
                    "conflicting_ip_mac_mappings": 3, "unique_source_macs": 10,
                    "requests": 80, "replies": 20}
        comparison = compare_conditions(normal, abnormal)
        self.assertIn("deltas", comparison)
        self.assertEqual(comparison["deltas"]["total_packets"], 90)
        self.assertGreater(len(comparison["impact_summary"]), 0)


class TestDisruptionIndicator(unittest.TestCase):

    def test_zero_profile(self):
        """Empty profile should produce zero disruption."""
        profile = {"conflicting_ip_mac_mappings": 0, "packets_per_second": 0, "unique_source_macs": 0}
        score = compute_disruption_indicator(profile)
        self.assertAlmostEqual(score, 0.0)

    def test_high_disruption(self):
        """All indicators maxed should produce 1.0."""
        profile = {"conflicting_ip_mac_mappings": 10, "packets_per_second": 200, "unique_source_macs": 50}
        score = compute_disruption_indicator(profile)
        self.assertAlmostEqual(score, 1.0)

    def test_partial_disruption(self):
        """Only conflicts, no rate or MAC issues."""
        profile = {"conflicting_ip_mac_mappings": 5, "packets_per_second": 0, "unique_source_macs": 0}
        score = compute_disruption_indicator(profile)
        self.assertGreater(score, 0)
        self.assertLess(score, 1.0)


class TestAnalyzeDDoSImpact(unittest.TestCase):

    def _make_packets(self, count, ip, mac, op, label, start_ts="2026-01-01T00:00:00"):
        """Helper to create a list of packets."""
        from datetime import datetime, timedelta
        base = datetime.fromisoformat(start_ts)
        packets = []
        for i in range(count):
            packets.append({
                "timestamp": (base + timedelta(seconds=i * 0.5)).isoformat(),
                "sender_ip": ip,
                "sender_mac": mac,
                "target_ip": "10.0.0.1",
                "target_mac": "ff:ff:ff:ff:ff:ff",
                "operation": op,
                "label": label,
            })
        return packets

    def test_basic_impact_analysis(self):
        normal = self._make_packets(20, "10.0.0.1", "aa:bb:cc:dd:ee:01", "request", "normal")
        suspicious = self._make_packets(50, "10.0.0.1", "aa:bb:cc:dd:ee:99", "reply", "gateway_spoofing",
                                        start_ts="2026-01-01T00:01:00")
        result = analyze_ddos_impact(normal, suspicious)

        self.assertIn("normal_arp_rate", result)
        self.assertIn("suspicious_arp_rate", result)
        self.assertIn("rate_increase_percent", result)
        self.assertIn("affected_hosts", result)
        self.assertIn("suspicious_events", result)
        self.assertIn("attack_duration_seconds", result)
        self.assertIn("pre_mitigation_disruption", result)
        self.assertEqual(result["data_source"], "controlled synthetic evaluation")
        self.assertGreater(result["affected_hosts"], 0)

    def test_impact_with_empty_data(self):
        """Should not crash with empty input."""
        result = analyze_ddos_impact([], [])
        self.assertEqual(result["normal_arp_rate"], 0)
        self.assertEqual(result["suspicious_arp_rate"], 0)
        self.assertEqual(result["affected_hosts"], 0)

    def test_impact_with_post_mitigation(self):
        normal = self._make_packets(10, "10.0.0.1", "aa:bb:cc:dd:ee:01", "request", "normal")
        suspicious = self._make_packets(30, "10.0.0.1", "aa:bb:cc:dd:ee:99", "reply", "gateway_spoofing")
        post_mit = self._make_packets(10, "10.0.0.1", "aa:bb:cc:dd:ee:01", "request", "normal",
                                      start_ts="2026-01-01T00:05:00")

        result = analyze_ddos_impact(normal, suspicious, post_mitigation_data=post_mit)
        self.assertIsNotNone(result["post_mitigation_disruption"])
        self.assertIsNotNone(result["improvement_percent"])

    def test_impact_without_post_mitigation(self):
        normal = self._make_packets(10, "10.0.0.1", "aa:bb:cc:dd:ee:01", "request", "normal")
        suspicious = self._make_packets(10, "10.0.0.1", "aa:bb:cc:dd:ee:99", "reply", "spoofing")
        result = analyze_ddos_impact(normal, suspicious)
        self.assertIsNone(result["post_mitigation_disruption"])
        self.assertIn("post_mitigation_note", result)


class TestCompareMitigationPhases(unittest.TestCase):

    def _make_packets(self, count, ip, mac, op, label):
        from datetime import datetime, timedelta
        base = datetime.fromisoformat("2026-01-01T00:00:00")
        return [
            {
                "timestamp": (base + timedelta(seconds=i)).isoformat(),
                "sender_ip": ip, "sender_mac": mac,
                "target_ip": "10.0.0.1", "target_mac": "ff:ff:ff:ff:ff:ff",
                "operation": op, "label": label,
            }
            for i in range(count)
        ]

    def test_two_phases(self):
        normal = self._make_packets(10, "10.0.0.1", "aa:bb:cc:dd:ee:01", "request", "normal")
        suspicious = self._make_packets(20, "10.0.0.1", "aa:bb:cc:dd:ee:99", "reply", "spoofing")
        phases = compare_mitigation_phases(normal, suspicious)

        self.assertIn("normal", phases)
        self.assertIn("suspicious_activity", phases)
        self.assertIn("post_mitigation", phases)
        self.assertIn("note", phases["post_mitigation"])

    def test_three_phases(self):
        normal = self._make_packets(10, "10.0.0.1", "aa:bb:cc:dd:ee:01", "request", "normal")
        suspicious = self._make_packets(20, "10.0.0.1", "aa:bb:cc:dd:ee:99", "reply", "spoofing")
        post_mit = self._make_packets(10, "10.0.0.1", "aa:bb:cc:dd:ee:01", "request", "normal")
        phases = compare_mitigation_phases(normal, suspicious, post_mit)

        self.assertIn("arp_rate_pps", phases["post_mitigation"])
        self.assertNotIn("note", phases["post_mitigation"])


class TestBuildDDoSImpactReport(unittest.TestCase):

    def test_complete_report(self):
        normal = [
            {"timestamp": "2026-01-01T00:00:00", "operation": "request",
             "sender_ip": "10.0.0.1", "sender_mac": "aa:bb:cc:dd:ee:01",
             "target_ip": "10.0.0.2", "target_mac": "ff:ff:ff:ff:ff:ff", "label": "normal"},
        ]
        abnormal = [
            {"timestamp": "2026-01-01T00:00:01", "operation": "reply",
             "sender_ip": "10.0.0.1", "sender_mac": "aa:bb:cc:dd:ee:99",
             "target_ip": "10.0.0.2", "target_mac": "ff:ff:ff:ff:ff:ff", "label": "spoofing"},
        ]
        report = build_ddos_impact_report(normal, abnormal, [])
        self.assertIn("traffic_comparison", report)
        self.assertIn("detection_summary", report)
        self.assertIn("ddos_impact_analysis", report)
        self.assertIn("phase_comparison", report)
        self.assertIn("mitigation", report)

    def test_report_with_mitigation(self):
        report = build_ddos_impact_report([], [], [],
                                          mitigation_data={"triggered": True, "result": "OK"})
        self.assertTrue(report["mitigation"]["triggered"])


# ═══════════════════════════════════════════════════════════════════════
# ADAPTER BEHAVIOR
# ═══════════════════════════════════════════════════════════════════════


class TestStubDetector(unittest.TestCase):

    def test_stub_returns_no_events(self):
        stub = StubDetector()
        events = stub.analyze_packet({"sender_ip": "10.0.0.1"})
        self.assertEqual(events, [])

    def test_stub_batch_returns_no_events(self):
        stub = StubDetector()
        events = stub.analyze_batch([
            {"sender_ip": "10.0.0.1"},
            {"sender_ip": "10.0.0.2"},
        ])
        self.assertEqual(events, [])

    def test_stub_statistics(self):
        stub = StubDetector()
        stub.analyze_batch([{"sender_ip": "10.0.0.1"}] * 5)
        stats = stub.get_statistics()
        self.assertEqual(stats["total_detections"], 0)
        self.assertEqual(stats["packets_processed"], 5)

    def test_stub_reset(self):
        stub = StubDetector()
        stub.analyze_packet({"sender_ip": "10.0.0.1"})
        stub.reset()
        stats = stub.get_statistics()
        self.assertEqual(stats["packets_processed"], 0)

    def test_stub_is_subclass(self):
        self.assertTrue(issubclass(StubDetector, DetectionAdapter))


class TestDetectionEvent(unittest.TestCase):

    def test_to_dict(self):
        e = DetectionEvent(
            event_type="IP_MAC_MAPPING_CHANGE",
            severity="MEDIUM",
            reason="Test reason",
            affected_ip="10.0.0.1",
            affected_mac="aa:bb:cc:dd:ee:ff",
        )
        d = e.to_dict()
        self.assertEqual(d["event_type"], "IP_MAC_MAPPING_CHANGE")
        self.assertEqual(d["severity"], "MEDIUM")
        self.assertEqual(d["affected_ip"], "10.0.0.1")

    def test_defaults(self):
        e = DetectionEvent(event_type="T", severity="LOW", reason="R")
        self.assertEqual(e.affected_ip, "")
        self.assertEqual(e.affected_mac, "")
        self.assertEqual(e.timestamp, "")
        self.assertEqual(e.additional_info, {})


class TestMitigationResult(unittest.TestCase):

    def test_default_values(self):
        m = MitigationResult()
        self.assertFalse(m.triggered)
        self.assertIsNone(m.start_time)

    def test_to_dict(self):
        m = MitigationResult(triggered=True, action_taken="ISOLATE_DEVICE")
        d = m.to_dict()
        self.assertTrue(d["triggered"])
        self.assertEqual(d["action_taken"], "ISOLATE_DEVICE")


# ═══════════════════════════════════════════════════════════════════════
# SCENARIOS
# ═══════════════════════════════════════════════════════════════════════


PERSON1_KEYS = {"timestamp", "sender_ip", "sender_mac",
                "target_ip", "target_mac", "operation", "label"}

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

    def test_all_packets_have_label(self):
        """Every packet must include a label field."""
        for cls in ALL_SCENARIO_CLASSES:
            with self.subTest(scenario=cls.name):
                sr = cls().generate()
                for pkt in sr.packets:
                    self.assertIn("label", pkt)
                    self.assertIsInstance(pkt["label"], str)
                    self.assertTrue(len(pkt["label"]) > 0)

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

    def test_attack_scenarios_have_correct_labels(self):
        """Attack scenario packets in attack phase should have
        non-normal labels."""
        attack_label_map = {
            IPMACConflictScenario: "ip_mac_conflict",
            GatewaySpoofingScenario: "gateway_spoofing",
            DuplicateIPScenario: "duplicate_ip",
            SuspiciousRepliesScenario: "suspicious_reply",
            HighARPRateScenario: "high_arp_rate",
        }
        for cls, expected_label in attack_label_map.items():
            with self.subTest(scenario=cls.name):
                sr = cls().generate()
                attack_labels = [
                    p["label"] for p in sr.packets
                    if p["label"] != "normal"
                ]
                self.assertGreater(len(attack_labels), 0,
                                   f"{cls.name} has no attack-labelled packets")
                for lbl in attack_labels:
                    self.assertEqual(lbl, expected_label)


# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════


class TestReportGenerator(unittest.TestCase):

    def _make_inputs(self):
        scenario_results = [
            {
                "scenario_name": "test_scenario",
                "description": "Test",
                "expected_detection": True,
                "actual_detected": True,
                "expected_severity": "HIGH",
                "detection_status": "PASS",
                "detection_reason": "test",
                "detected_attacker_ip": "10.0.0.1",
                "detected_attacker_mac": "aa:bb:cc:dd:ee:ff",
                "detection_latency_ms": 15.0,
                "num_events": 3,
                "is_attack": True,
                "total_packets": 35,
            },
        ]
        metrics = {
            "total_scenarios": 1, "true_positives": 1,
            "true_negatives": 0, "false_positives": 0,
            "false_negatives": 0, "accuracy": 1.0,
            "detection_rate": 1.0,
            "false_positive_rate": 0.0, "false_negative_rate": 0.0,
            "precision": 1.0, "recall": 1.0, "f1_score": 1.0,
        }
        timing = {
            "samples": 1, "average_detection_time_ms": 15.0,
            "min_detection_time_ms": 15.0, "max_detection_time_ms": 15.0,
            "median_detection_time_ms": 15.0, "stddev_detection_time_ms": 0.0,
        }
        fp = {"total_false_positives": 0, "total_false_negatives": 0,
              "false_positive_scenarios": [], "false_negative_scenarios": [],
              "false_positives_by_rule": {}, "false_negatives_by_expected_type": {}}
        return scenario_results, metrics, timing, fp

    def test_generates_all_files(self):
        scenario_results, metrics, timing, fp = self._make_inputs()
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(
                scenario_results, metrics, timing, fp,
                output_dir=tmpdir,
            )
            self.assertIn("json", paths)
            self.assertIn("csv", paths)
            self.assertIn("txt", paths)
            self.assertIn("md", paths)
            for fmt in ["json", "csv", "txt", "md"]:
                self.assertTrue(os.path.isfile(paths[fmt]),
                                f"{fmt} report file not created")

    def test_json_is_valid(self):
        scenario_results, metrics, timing, fp = self._make_inputs()
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(
                scenario_results, metrics, timing, fp,
                output_dir=tmpdir,
            )
            with open(paths["json"]) as f:
                report = json.load(f)
            self.assertIn("detection_metrics", report)
            self.assertIn("scenarios", report)
            self.assertIn("report_metadata", report)
            self.assertEqual(report["report_metadata"]["data_classification"],
                             "controlled synthetic evaluation")

    def test_markdown_contains_sections(self):
        scenario_results, metrics, timing, fp = self._make_inputs()
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(
                scenario_results, metrics, timing, fp,
                output_dir=tmpdir,
            )
            with open(paths["md"], encoding="utf-8") as f:
                md = f.read()
            self.assertIn("# ARPShield", md)
            self.assertIn("## 3. Detection Metrics", md)
            self.assertIn("## 4. Detection Latency", md)
            self.assertIn("## 5. False Positive Analysis", md)
            self.assertIn("## 7. Limitations", md)
            self.assertIn("## 8. Conclusions", md)

    def test_latest_json_overwritten(self):
        scenario_results, metrics, timing, fp = self._make_inputs()
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(
                scenario_results, metrics, timing, fp,
                output_dir=tmpdir,
            )
            self.assertIn("latest_json", paths)
            self.assertTrue(os.path.isfile(paths["latest_json"]))

    def test_report_with_ddos_impact(self):
        """Report should include DDoS impact section when provided."""
        scenario_results, metrics, timing, fp = self._make_inputs()
        ddos = {
            "traffic_comparison": {
                "impact_summary": ["Rate increased 5x"],
                "normal": {"packets_per_second": 2.0},
                "abnormal": {"packets_per_second": 10.0},
            },
            "detection_summary": {
                "total_events": 5,
                "affected_device_count": 2,
            },
            "ddos_impact_analysis": {
                "normal_arp_rate": 2.0,
                "suspicious_arp_rate": 10.0,
                "rate_increase_percent": 400.0,
                "affected_hosts": 2,
                "suspicious_events": 15,
                "attack_duration_seconds": 5.0,
                "conflicting_mappings": 1,
                "pre_mitigation_disruption": 0.5,
                "post_mitigation_disruption": None,
                "improvement_percent": None,
            },
            "phase_comparison": {
                "normal": {"arp_rate_pps": 2.0, "suspicious_events": 0,
                           "affected_hosts": 3, "disruption_indicator": 0.01},
                "suspicious_activity": {"arp_rate_pps": 10.0, "suspicious_events": 15,
                                        "affected_hosts": 5, "disruption_indicator": 0.5},
                "post_mitigation": {"note": "Person 4 mitigation data not yet available."},
            },
            "mitigation": {"triggered": False, "note": "Not available"},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(
                scenario_results, metrics, timing, fp,
                ddos_impact=ddos, output_dir=tmpdir,
            )
            with open(paths["md"], encoding="utf-8") as f:
                md = f.read()
            self.assertIn("## 6. DDoS / Network Impact Analysis", md)
            self.assertIn("Impact Metrics", md)


# ═══════════════════════════════════════════════════════════════════════
# VISUALIZATION (availability check)
# ═══════════════════════════════════════════════════════════════════════


class TestVisualizationImport(unittest.TestCase):

    def test_visualize_module_importable(self):
        """The visualization module should be importable."""
        from testing.evaluation import visualize
        self.assertTrue(hasattr(visualize, "generate_charts"))


if __name__ == "__main__":
    unittest.main()
