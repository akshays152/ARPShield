"""
Unit tests for Person 3's detection metrics, timing, and adapter.

Does NOT import from detection/, prevention/, or ml/.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from testing.evaluation.detection_metrics import (
    compute_confusion_values,
    compute_detection_metrics,
)
from testing.evaluation.detection_time import compute_detection_time_metrics
from testing.integration.detection_adapter import (
    DetectionAdapter, DetectionEvent, StubDetector, MitigationResult,
)


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
        self.assertAlmostEqual(m["detection_rate"], 0.5)
        self.assertAlmostEqual(m["false_positive_rate"], 0.5)
        self.assertAlmostEqual(m["precision"], 0.5)

    def test_empty_results(self):
        m = compute_detection_metrics([])
        self.assertEqual(m["total_scenarios"], 0)


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

    def test_single_detection(self):
        results = [
            {"actual_detected": True, "detection_latency_ms": 42.5},
        ]
        t = compute_detection_time_metrics(results)
        self.assertEqual(t["samples"], 1)
        self.assertAlmostEqual(t["average_detection_time_ms"], 42.5)
        self.assertAlmostEqual(t["stddev_detection_time_ms"], 0.0)


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


if __name__ == "__main__":
    unittest.main()
