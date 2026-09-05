"""
Unit tests for Person 3's report generator, false-positive analysis,
and DDoS impact analysis.

Does NOT import from detection/, prevention/, or ml/.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from testing.evaluation.report_generator import generate_report
from testing.evaluation.false_positive_analysis import analyze_false_positives
from testing.evaluation.ddos_impact import (
    analyze_traffic_profile,
    compare_conditions,
)


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


class TestDDoSImpactAnalysis(unittest.TestCase):

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


class TestReportGenerator(unittest.TestCase):

    def test_generates_all_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
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
                },
            ]
            metrics = {
                "total_scenarios": 1, "true_positives": 1,
                "true_negatives": 0, "false_positives": 0,
                "false_negatives": 0, "detection_rate": 1.0,
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

            paths = generate_report(
                scenario_results, metrics, timing, fp,
                output_dir=tmpdir,
            )

            self.assertIn("json", paths)
            self.assertIn("csv", paths)
            self.assertIn("txt", paths)
            self.assertTrue(os.path.isfile(paths["json"]))
            self.assertTrue(os.path.isfile(paths["csv"]))
            self.assertTrue(os.path.isfile(paths["txt"]))

            # Verify JSON is valid
            with open(paths["json"]) as f:
                report = json.load(f)
            self.assertIn("detection_metrics", report)
            self.assertIn("scenarios", report)


if __name__ == "__main__":
    unittest.main()
