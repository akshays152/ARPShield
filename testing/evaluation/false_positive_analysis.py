"""
False Positive Analysis — Detailed breakdown of FP and FN by rule and scenario.

Provides per-rule and per-scenario insight into which detection rules
produce false positives and which attack scenarios are missed.
"""

from typing import Dict, Any, List
from collections import defaultdict


def analyze_false_positives(
    results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Detailed false-positive and false-negative analysis.

    Each entry in *results* should contain:
        - scenario_name: str
        - expected_detection: bool
        - actual_detected: bool
        - detection_events: list[dict]   (DetectionResult.to_dict() entries)
        - expected_event_types: list[str]

    Returns a structured breakdown.
    """
    fp_scenarios: List[Dict[str, Any]] = []
    fn_scenarios: List[Dict[str, Any]] = []

    fp_by_rule: Dict[str, int] = defaultdict(int)
    fn_by_expected_type: Dict[str, int] = defaultdict(int)

    for r in results:
        expected = r["expected_detection"]
        actual = r["actual_detected"]
        events = r.get("detection_events", [])

        if not expected and actual:
            # False positive
            fp_scenarios.append({
                "scenario": r["scenario_name"],
                "unexpected_events": [
                    {
                        "event_type": e.get("event_type", "UNKNOWN"),
                        "severity": e.get("severity", "UNKNOWN"),
                        "reason": e.get("reason", ""),
                    }
                    for e in events
                ],
            })
            for e in events:
                fp_by_rule[e.get("event_type", "UNKNOWN")] += 1

        if expected and not actual:
            # False negative
            fn_scenarios.append({
                "scenario": r["scenario_name"],
                "missed_event_types": r.get("expected_event_types", []),
            })
            for et in r.get("expected_event_types", []):
                fn_by_expected_type[et] += 1

    return {
        "total_false_positives": len(fp_scenarios),
        "total_false_negatives": len(fn_scenarios),
        "false_positive_scenarios": fp_scenarios,
        "false_negative_scenarios": fn_scenarios,
        "false_positives_by_rule": dict(fp_by_rule),
        "false_negatives_by_expected_type": dict(fn_by_expected_type),
    }
