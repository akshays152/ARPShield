"""
Detection Time — Latency analysis for the rule-based detection engine.

Measures how quickly the detection engine identifies an attack after
the first malicious packet appears in the scenario.
"""

from typing import Dict, Any, List
import statistics


def compute_detection_time_metrics(
    results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute detection latency statistics.

    Each entry in *results* must contain:
        - actual_detected: bool
        - detection_latency_ms: float | None  (milliseconds)

    Returns aggregate timing metrics.
    """
    latencies = [
        r["detection_latency_ms"]
        for r in results
        if r.get("actual_detected") and r.get("detection_latency_ms") is not None
    ]

    if not latencies:
        return {
            "samples": 0,
            "average_detection_time_ms": None,
            "min_detection_time_ms": None,
            "max_detection_time_ms": None,
            "median_detection_time_ms": None,
            "stddev_detection_time_ms": None,
        }

    return {
        "samples": len(latencies),
        "average_detection_time_ms": round(statistics.mean(latencies), 2),
        "min_detection_time_ms": round(min(latencies), 2),
        "max_detection_time_ms": round(max(latencies), 2),
        "median_detection_time_ms": round(statistics.median(latencies), 2),
        "stddev_detection_time_ms": (
            round(statistics.stdev(latencies), 2)
            if len(latencies) > 1 else 0.0
        ),
    }
