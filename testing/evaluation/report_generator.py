"""
Report Generator — Creates JSON, CSV and human-readable evaluation reports.

Aggregates detection metrics, timing data, false-positive analysis,
and DDoS impact analysis into a single comprehensive report.
"""

import csv
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


def generate_report(
    scenario_results: List[Dict[str, Any]],
    detection_metrics: Dict[str, Any],
    timing_metrics: Dict[str, Any],
    fp_analysis: Dict[str, Any],
    ddos_impact: Optional[Dict[str, Any]] = None,
    output_dir: str = "testing/results",
) -> Dict[str, str]:
    """Generate all report files and return their paths.

    Returns
    -------
    dict
        Mapping of report type to file path.
    """
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    paths = {}

    # ── 1. Full JSON report ──────────────────────────────────────────
    full_report = _build_full_report(
        scenario_results, detection_metrics, timing_metrics,
        fp_analysis, ddos_impact,
    )
    json_path = os.path.join(output_dir, f"evaluation_report_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2, default=str)
    paths["json"] = json_path

    # ── 2. CSV results ───────────────────────────────────────────────
    csv_path = os.path.join(output_dir, f"scenario_results_{ts}.csv")
    _write_csv(scenario_results, csv_path)
    paths["csv"] = csv_path

    # ── 3. Human-readable summary ────────────────────────────────────
    txt_path = os.path.join(output_dir, f"evaluation_summary_{ts}.txt")
    _write_text_summary(
        full_report, scenario_results, detection_metrics,
        timing_metrics, fp_analysis, ddos_impact, txt_path,
    )
    paths["txt"] = txt_path

    # ── 4. Latest symlink-style copy (always overwrite) ──────────────
    latest_json = os.path.join(output_dir, "latest_report.json")
    with open(latest_json, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2, default=str)
    paths["latest_json"] = latest_json

    return paths


def _build_full_report(
    scenario_results, detection_metrics, timing_metrics,
    fp_analysis, ddos_impact,
) -> Dict[str, Any]:
    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "module": "ARPShield Testing & Evaluation (Person 3)",
            "version": "1.0.0",
        },
        "test_environment": {
            "description": "Simulated ARP traffic in an isolated lab environment",
            "note": "All packets are synthetic test data — no live network was used",
        },
        "scenario_summary": {
            "total_scenarios": len(scenario_results),
            "attack_scenarios": sum(1 for r in scenario_results if r.get("is_attack")),
            "normal_scenarios": sum(1 for r in scenario_results if not r.get("is_attack")),
        },
        "scenarios": [
            {
                "scenario_name": r["scenario_name"],
                "description": r.get("description", ""),
                "expected_detection": r["expected_detection"],
                "actual_detected": r["actual_detected"],
                "expected_severity": r.get("expected_severity", ""),
                "detection_status": r.get("detection_status", ""),
                "detection_reason": r.get("detection_reason", ""),
                "detected_attacker_ip": r.get("detected_attacker_ip", ""),
                "detected_attacker_mac": r.get("detected_attacker_mac", ""),
                "detection_latency_ms": r.get("detection_latency_ms"),
                "num_events": r.get("num_events", 0),
            }
            for r in scenario_results
        ],
        "detection_metrics": detection_metrics,
        "timing_metrics": timing_metrics,
        "false_positive_analysis": fp_analysis,
        "ddos_impact_analysis": ddos_impact,
        "limitations": [
            "All tests use simulated packet data, not live captures",
            "Detection timing is measured within the simulation clock",
            "Person 4 mitigation data may not be available for all runs",
            "Results should be validated in an authorised lab environment",
        ],
        "conclusions": _generate_conclusions(detection_metrics, timing_metrics),
    }


def _generate_conclusions(metrics: Dict, timing: Dict) -> List[str]:
    conclusions = []
    dr = metrics.get("detection_rate", 0)
    fpr = metrics.get("false_positive_rate", 0)
    f1 = metrics.get("f1_score", 0)

    if dr >= 0.9:
        conclusions.append(f"Detection rate is {dr:.0%} — the rule-based engine reliably identifies simulated attacks")
    elif dr >= 0.7:
        conclusions.append(f"Detection rate is {dr:.0%} — adequate but some attack patterns are missed")
    else:
        conclusions.append(f"Detection rate is {dr:.0%} — significant improvement needed")

    if fpr == 0:
        conclusions.append("Zero false positives observed across all normal traffic scenarios")
    elif fpr < 0.1:
        conclusions.append(f"False positive rate is low ({fpr:.0%})")
    else:
        conclusions.append(f"False positive rate is {fpr:.0%} — rule tuning recommended")

    conclusions.append(f"Overall F1 score: {f1:.4f}")

    avg_t = timing.get("average_detection_time_ms")
    if avg_t is not None:
        conclusions.append(f"Average detection latency: {avg_t:.1f} ms")

    return conclusions


def _write_csv(results: List[Dict[str, Any]], path: str) -> None:
    fieldnames = [
        "scenario_name", "description", "expected_detection",
        "actual_detected", "expected_severity", "detection_status",
        "detection_reason", "detected_attacker_ip", "detected_attacker_mac",
        "detection_latency_ms", "num_events",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)


def _write_text_summary(
    full_report, scenario_results, metrics, timing, fp, ddos, path,
):
    lines = []
    lines.append("=" * 70)
    lines.append("  ARPShield — Testing & Evaluation Report (Person 3)")
    lines.append("=" * 70)
    lines.append(f"  Generated: {full_report['report_metadata']['generated_at']}")
    lines.append("")

    lines.append("─── TEST SCENARIOS ──────────────────────────────────────")
    for r in scenario_results:
        status = "✅ PASS" if r.get("detection_status") == "PASS" else "❌ FAIL"
        lines.append(f"  [{status}] {r['scenario_name']}")
        lines.append(f"        Expected detection: {r['expected_detection']}  |  Actual: {r['actual_detected']}")
        if r.get("detection_latency_ms") is not None:
            lines.append(f"        Detection latency: {r['detection_latency_ms']:.1f} ms")
    lines.append("")

    lines.append("─── DETECTION METRICS ───────────────────────────────────")
    lines.append(f"  True Positives:       {metrics.get('true_positives', 0)}")
    lines.append(f"  True Negatives:       {metrics.get('true_negatives', 0)}")
    lines.append(f"  False Positives:      {metrics.get('false_positives', 0)}")
    lines.append(f"  False Negatives:      {metrics.get('false_negatives', 0)}")
    lines.append(f"  Detection Rate:       {metrics.get('detection_rate', 0):.4f}")
    lines.append(f"  False Positive Rate:  {metrics.get('false_positive_rate', 0):.4f}")
    lines.append(f"  False Negative Rate:  {metrics.get('false_negative_rate', 0):.4f}")
    lines.append(f"  Precision:            {metrics.get('precision', 0):.4f}")
    lines.append(f"  Recall:               {metrics.get('recall', 0):.4f}")
    lines.append(f"  F1 Score:             {metrics.get('f1_score', 0):.4f}")
    lines.append("")

    lines.append("─── DETECTION TIMING ───────────────────────────────────")
    lines.append(f"  Average:  {timing.get('average_detection_time_ms', 'N/A')} ms")
    lines.append(f"  Minimum:  {timing.get('min_detection_time_ms', 'N/A')} ms")
    lines.append(f"  Maximum:  {timing.get('max_detection_time_ms', 'N/A')} ms")
    lines.append(f"  Median:   {timing.get('median_detection_time_ms', 'N/A')} ms")
    lines.append("")

    if fp.get("total_false_positives", 0) > 0 or fp.get("total_false_negatives", 0) > 0:
        lines.append("─── FALSE POSITIVE / NEGATIVE DETAIL ───────────────────")
        lines.append(f"  FP scenarios: {fp.get('total_false_positives', 0)}")
        lines.append(f"  FN scenarios: {fp.get('total_false_negatives', 0)}")
        lines.append("")

    if ddos:
        lines.append("─── DDoS / NETWORK IMPACT ANALYSIS ─────────────────────")
        tc = ddos.get("traffic_comparison", {})
        for obs in tc.get("impact_summary", []):
            lines.append(f"  • {obs}")
        ds = ddos.get("detection_summary", {})
        lines.append(f"  Total detection events: {ds.get('total_events', 0)}")
        lines.append(f"  Affected devices: {ds.get('affected_device_count', 0)}")
        mit = ddos.get("mitigation", {})
        if mit.get("triggered"):
            lines.append(f"  Mitigation triggered: YES")
            lines.append(f"  Mitigation result: {mit.get('result', 'N/A')}")
        else:
            lines.append(f"  Mitigation: {mit.get('note', 'Not available')}")
        lines.append("")

    lines.append("─── CONCLUSIONS ────────────────────────────────────────")
    for c in full_report.get("conclusions", []):
        lines.append(f"  • {c}")
    lines.append("")
    lines.append("=" * 70)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
