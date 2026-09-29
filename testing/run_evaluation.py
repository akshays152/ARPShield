"""
ARPShield -- Test Evaluation Runner (Person 3)

Main entry point that:
  1. Runs all controlled test scenarios
  2. Feeds packets into Person 2's detector via the DetectionAdapter
  3. Collects detection results
  4. Compares expected vs actual outcomes
  5. Calculates cybersecurity detection metrics
  6. Performs DDoS / network-impact analysis
  7. Optionally consumes Person 4's mitigation data
  8. Generates JSON, CSV, Markdown and human-readable reports
  9. Generates evaluation charts (if matplotlib is available)

Usage (standalone with stub detector):
    python -m testing.run_evaluation

Usage (with Person 2's detector connected):
    from testing.run_evaluation import run_evaluation
    from testing.integration.detection_adapter import DetectionAdapter

    class Person2Detector(DetectionAdapter):
        ...  # Person 2 implements this

    results = run_evaluation(detector=Person2Detector())
"""

import os
import sys
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# Ensure project root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from testing.integration.detection_adapter import (
    DetectionAdapter, StubDetector, MitigationResult,
)

from testing.scenarios.normal_arp import NormalARPScenario
from testing.scenarios.ip_mac_conflict import IPMACConflictScenario
from testing.scenarios.gateway_spoofing import GatewaySpoofingScenario
from testing.scenarios.duplicate_ip import DuplicateIPScenario
from testing.scenarios.suspicious_replies import SuspiciousRepliesScenario
from testing.scenarios.high_arp_rate import HighARPRateScenario
from testing.scenarios.base import ScenarioResult

from testing.evaluation.detection_metrics import compute_detection_metrics
from testing.evaluation.detection_time import compute_detection_time_metrics
from testing.evaluation.false_positive_analysis import analyze_false_positives
from testing.evaluation.ddos_impact import build_ddos_impact_report
from testing.evaluation.report_generator import generate_report

try:
    from testing.evaluation.visualize import generate_charts
    CHARTS_AVAILABLE = True
except ImportError:
    CHARTS_AVAILABLE = False


# ── All registered scenarios ──────────────────────────────────────────
ALL_SCENARIOS = [
    NormalARPScenario(),
    IPMACConflictScenario(),
    GatewaySpoofingScenario(),
    DuplicateIPScenario(),
    SuspiciousRepliesScenario(),
    HighARPRateScenario(),
]


def _run_scenario_through_detector(
    scenario_result: ScenarioResult,
    detector: DetectionAdapter,
) -> Dict[str, Any]:
    """Feed one scenario's packets into the detector adapter and
    collect the outcome.
    """
    detector.reset()
    packets = scenario_result.packets

    start_wall = time.perf_counter_ns()
    all_events = detector.analyze_batch(packets)
    end_wall = time.perf_counter_ns()
    wall_ms = (end_wall - start_wall) / 1e6

    actual_detected = len(all_events) > 0

    # Detection latency (from adapter events)
    detection_latency_ms: Optional[float] = None
    if scenario_result.is_attack and all_events:
        # Use wall time as a proxy; real latency requires Person 2
        # to timestamp detection events
        detection_latency_ms = wall_ms

    # Determine pass/fail
    expected = scenario_result.expected_detection
    if expected == actual_detected:
        detection_status = "PASS"
    else:
        detection_status = "FAIL"

    # Extract attacker info from first event
    attacker_ip = ""
    attacker_mac = ""
    detection_reason = ""
    if all_events:
        first = all_events[0]
        attacker_ip = first.affected_ip
        attacker_mac = first.affected_mac
        detection_reason = first.reason

    return {
        "scenario_name": scenario_result.scenario_name,
        "description": scenario_result.description,
        "expected_detection": expected,
        "expected_severity": scenario_result.expected_severity,
        "expected_event_types": scenario_result.expected_event_types,
        "actual_detected": actual_detected,
        "detection_status": detection_status,
        "detection_reason": detection_reason,
        "detected_attacker_ip": attacker_ip,
        "detected_attacker_mac": attacker_mac,
        "detection_latency_ms": detection_latency_ms,
        "num_events": len(all_events),
        "is_attack": scenario_result.is_attack,
        "detection_events": [e.to_dict() for e in all_events],
        "total_packets": len(packets),
        "wall_time_ms": round(wall_ms, 2),
        # Keep raw packets for DDoS analysis (internal use)
        "_packets": packets,
    }


def run_evaluation(
    scenarios=None,
    detector: Optional[DetectionAdapter] = None,
    mitigation: Optional[MitigationResult] = None,
    output_dir: str = "testing/results",
) -> Dict[str, Any]:
    """Run the full evaluation pipeline.

    Parameters
    ----------
    scenarios : list, optional
        Scenario instances to run.  Defaults to ALL_SCENARIOS.
    detector : DetectionAdapter, optional
        Person 2's detection engine adapter.  Defaults to StubDetector.
    mitigation : MitigationResult, optional
        Person 4's mitigation data, if available.
    output_dir : str
        Directory for report output.

    Returns
    -------
    dict
        Complete evaluation results.
    """
    scenarios = scenarios or ALL_SCENARIOS
    det = detector or StubDetector()

    detector_name = type(det).__name__
    is_stub = isinstance(det, StubDetector)

    print("=" * 70)
    print("  ARPShield -- Testing & Evaluation Runner (Person 3)")
    print("=" * 70)
    print(f"  Scenarios:  {len(scenarios)}")
    print(f"  Detector:   {detector_name}", end="")
    if is_stub:
        print("  (Person 2 not connected -- using stub)")
    else:
        print()
    print(f"  Output dir: {output_dir}")
    print()

    # ── 1. Generate and run scenarios ─────────────────────────────────
    results: List[Dict[str, Any]] = []
    normal_packets_all: List[Dict[str, Any]] = []
    abnormal_packets_all: List[Dict[str, Any]] = []

    for scenario in scenarios:
        print(f"  Running: {scenario.name} ... ", end="", flush=True)
        sr = scenario.generate()
        outcome = _run_scenario_through_detector(sr, det)
        results.append(outcome)

        # Collect packets for DDoS impact analysis
        if sr.is_attack:
            abnormal_packets_all.extend(outcome["_packets"])
        else:
            normal_packets_all.extend(outcome["_packets"])

        status = "PASS" if outcome["detection_status"] == "PASS" else "FAIL"
        print(f"  [{status}]  (events={outcome['num_events']}, packets={outcome['total_packets']})")

    print()

    # ── 2. Compute metrics ────────────────────────────────────────────
    detection_metrics = compute_detection_metrics(results)
    timing_metrics = compute_detection_time_metrics(results)
    fp_analysis = analyze_false_positives(results)

    print("--- Detection Metrics -----------------------------------------")
    print(f"  TP={detection_metrics['true_positives']}  "
          f"TN={detection_metrics['true_negatives']}  "
          f"FP={detection_metrics['false_positives']}  "
          f"FN={detection_metrics['false_negatives']}")
    print(f"  Accuracy:        {detection_metrics['accuracy']:.4f}")
    print(f"  Detection Rate:  {detection_metrics['detection_rate']:.4f}")
    print(f"  Precision:       {detection_metrics['precision']:.4f}")
    print(f"  Recall:          {detection_metrics['recall']:.4f}")
    print(f"  F1 Score:        {detection_metrics['f1_score']:.4f}")
    print(f"  FP Rate:         {detection_metrics['false_positive_rate']:.4f}")
    print()

    # ── 3. False positive summary ─────────────────────────────────────
    total_normal = sum(1 for r in results if not r.get("is_attack"))
    total_normal_flagged = fp_analysis.get("total_false_positives", 0)
    print("--- False Positive Analysis -----------------------------------")
    print(f"  Normal scenarios:     {total_normal}")
    print(f"  Incorrectly flagged:  {total_normal_flagged}")
    fp_rate_display = (total_normal_flagged / max(total_normal, 1)) * 100
    print(f"  False Positive Rate:  {fp_rate_display:.1f}%")
    if fp_analysis.get("total_false_negatives", 0) > 0:
        print(f"  Missed attacks (FN):  {fp_analysis['total_false_negatives']}")
    print()

    # ── 4. DDoS impact analysis ───────────────────────────────────────
    all_detection_events = []
    for r in results:
        all_detection_events.extend(r.get("detection_events", []))

    avg_latency = timing_metrics.get("average_detection_time_ms")

    mitigation_data = mitigation.to_dict() if mitigation else None

    ddos_impact = build_ddos_impact_report(
        normal_packets=normal_packets_all,
        abnormal_packets=abnormal_packets_all,
        detection_events=all_detection_events,
        detection_time_ms=avg_latency,
        mitigation_data=mitigation_data,
    )

    print("--- DDoS Impact Analysis --------------------------------------")
    tc = ddos_impact.get("traffic_comparison", {})
    for obs in tc.get("impact_summary", []):
        print(f"  * {obs}")
    ds = ddos_impact.get("detection_summary", {})
    print(f"  Total detection events: {ds.get('total_events', 0)}")
    print(f"  Affected devices: {ds.get('affected_device_count', 0)}")

    # Extended metrics
    ext = ddos_impact.get("ddos_impact_analysis", {})
    if ext:
        print(f"  Normal ARP rate:       {ext.get('normal_arp_rate', 'N/A')} pps")
        print(f"  Suspicious ARP rate:   {ext.get('suspicious_arp_rate', 'N/A')} pps")
        print(f"  Rate increase:         {ext.get('rate_increase_percent', 'N/A')}%")
        print(f"  Affected hosts:        {ext.get('affected_hosts', 'N/A')}")
        print(f"  Attack duration:       {ext.get('attack_duration_seconds', 'N/A')} s")
        print(f"  Pre-mitigation disruption:  {ext.get('pre_mitigation_disruption', 'N/A')}")
    print()

    # ── 5. Generate reports ───────────────────────────────────────────
    # Strip internal _packets before report generation
    clean_results = [
        {k: v for k, v in r.items() if not k.startswith("_")}
        for r in results
    ]

    report_paths = generate_report(
        scenario_results=clean_results,
        detection_metrics=detection_metrics,
        timing_metrics=timing_metrics,
        fp_analysis=fp_analysis,
        ddos_impact=ddos_impact,
        output_dir=output_dir,
    )

    print("--- Reports Generated -----------------------------------------")
    for kind, path in report_paths.items():
        print(f"  {kind:12s} -> {path}")

    # ── 6. Generate charts ───────────────────────────────────────────
    chart_paths = {}
    if CHARTS_AVAILABLE:
        chart_paths = generate_charts(
            scenario_results=clean_results,
            detection_metrics=detection_metrics,
            timing_metrics=timing_metrics,
            ddos_impact=ddos_impact,
            output_dir=output_dir,
            is_synthetic=True,
        )
        if "error" not in chart_paths:
            print()
            print("--- Charts Generated ------------------------------------------")
            for name, path in chart_paths.items():
                print(f"  {name:25s} -> {path}")
    print()

    if is_stub:
        print("  NOTE: Evaluation executed using StubDetector because")
        print("  Person 2's detection engine is not yet integrated.")
        print("  All attack scenarios show as FN (False Negative).")
        print("  Connect Person 2's detector via the DetectionAdapter")
        print("  interface for real evaluation.")
        print()

    print("=" * 70)

    return {
        "scenario_results": clean_results,
        "detection_metrics": detection_metrics,
        "timing_metrics": timing_metrics,
        "fp_analysis": fp_analysis,
        "ddos_impact": ddos_impact,
        "report_paths": report_paths,
        "chart_paths": chart_paths,
        "detector_used": detector_name,
    }


if __name__ == "__main__":
    run_evaluation()
