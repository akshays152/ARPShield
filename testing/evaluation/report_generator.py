"""
Report Generator — Creates JSON, CSV, Markdown and human-readable evaluation reports.

Aggregates detection metrics, timing data, false-positive analysis,
and DDoS impact analysis into a single comprehensive report.

Outputs:
    - JSON  (machine-readable full report)
    - CSV   (scenario-level results table)
    - TXT   (human-readable plain-text summary)
    - MD    (human-readable Markdown report)
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

    # ── 3. Human-readable plain-text summary ─────────────────────────
    txt_path = os.path.join(output_dir, f"evaluation_summary_{ts}.txt")
    _write_text_summary(
        full_report, scenario_results, detection_metrics,
        timing_metrics, fp_analysis, ddos_impact, txt_path,
    )
    paths["txt"] = txt_path

    # ── 4. Markdown report ───────────────────────────────────────────
    md_path = os.path.join(output_dir, f"evaluation_report_{ts}.md")
    _write_markdown_report(
        full_report, scenario_results, detection_metrics,
        timing_metrics, fp_analysis, ddos_impact, md_path,
    )
    paths["md"] = md_path

    # ── 5. Latest symlink-style copy (always overwrite) ──────────────
    latest_json = os.path.join(output_dir, "latest_report.json")
    with open(latest_json, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2, default=str)
    paths["latest_json"] = latest_json

    return paths


def _build_full_report(
    scenario_results, detection_metrics, timing_metrics,
    fp_analysis, ddos_impact,
) -> Dict[str, Any]:
    # Identify whether a stub detector was used
    detector_info = "Unknown"
    for r in scenario_results:
        if r.get("is_attack") and not r.get("actual_detected"):
            detector_info = "StubDetector (Person 2 not connected)"
            break

    return {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "module": "ARPShield Testing & Evaluation (Person 3)",
            "version": "2.0.0",
            "data_classification": "controlled synthetic evaluation",
        },
        "test_environment": {
            "description": "Simulated ARP traffic in an isolated lab environment",
            "note": "All packets are synthetic test data — no live network was used",
            "detector": detector_info,
        },
        "scenario_summary": {
            "total_scenarios": len(scenario_results),
            "attack_scenarios": sum(1 for r in scenario_results if r.get("is_attack")),
            "normal_scenarios": sum(1 for r in scenario_results if not r.get("is_attack")),
            "total_packets": sum(r.get("total_packets", 0) for r in scenario_results),
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
                "total_packets": r.get("total_packets", 0),
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
            "ARP spoofing and DDoS are distinct attacks — this module "
            "evaluates network-disruption impact, not DDoS attribution",
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
        "detection_latency_ms", "num_events", "total_packets",
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
    lines.append(f"  Data Classification: {full_report['report_metadata']['data_classification']}")
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
    lines.append(f"  Accuracy:             {metrics.get('accuracy', 0):.4f}")
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

        # Extended impact
        ext = ddos.get("ddos_impact_analysis", {})
        if ext:
            lines.append(f"  Normal ARP rate:       {ext.get('normal_arp_rate', 'N/A')} pps")
            lines.append(f"  Suspicious ARP rate:   {ext.get('suspicious_arp_rate', 'N/A')} pps")
            lines.append(f"  Rate increase:         {ext.get('rate_increase_percent', 'N/A')}%")
            lines.append(f"  Affected hosts:        {ext.get('affected_hosts', 'N/A')}")
            lines.append(f"  Attack duration:       {ext.get('attack_duration_seconds', 'N/A')} s")
            lines.append(f"  Pre-mitigation disruption:  {ext.get('pre_mitigation_disruption', 'N/A')}")
            lines.append(f"  Post-mitigation disruption: {ext.get('post_mitigation_disruption', 'N/A')}")

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


# ── NEW: Markdown report ─────────────────────────────────────────────


def _write_markdown_report(
    full_report, scenario_results, metrics, timing, fp, ddos, path,
):
    """Generate a comprehensive Markdown evaluation report."""
    lines = []

    lines.append("# ARPShield — Testing & Evaluation Report (Person 3)")
    lines.append("")
    lines.append(f"**Generated:** {full_report['report_metadata']['generated_at']}")
    lines.append(f"**Data Classification:** {full_report['report_metadata']['data_classification']}")
    lines.append(f"**Detector:** {full_report['test_environment'].get('detector', 'Unknown')}")
    lines.append("")
    lines.append("> **Note:** ARP spoofing and DDoS are distinct attacks. This module evaluates ")
    lines.append("> the network disruption / availability impact associated with suspicious ARP ")
    lines.append("> activity and does not claim that every ARP spoofing event is a DDoS attack.")
    lines.append("")

    # ── 1. Test Configuration
    lines.append("## 1. Test Configuration")
    lines.append("")
    ss = full_report.get("scenario_summary", {})
    lines.append(f"- **Total scenarios:** {ss.get('total_scenarios', 0)}")
    lines.append(f"- **Attack scenarios:** {ss.get('attack_scenarios', 0)}")
    lines.append(f"- **Normal scenarios:** {ss.get('normal_scenarios', 0)}")
    lines.append(f"- **Total packets:** {ss.get('total_packets', 0)}")
    lines.append("")

    # ── 2. Scenario Results
    lines.append("## 2. Scenario Results")
    lines.append("")
    lines.append("| Scenario | Expected | Actual | Status | Severity | Events | Packets |")
    lines.append("|----------|----------|--------|--------|----------|--------|---------|")
    for r in scenario_results:
        status = "PASS" if r.get("detection_status") == "PASS" else "FAIL"
        status_icon = "✅" if status == "PASS" else "❌"
        lines.append(
            f"| {r['scenario_name']} "
            f"| {r['expected_detection']} "
            f"| {r['actual_detected']} "
            f"| {status_icon} {status} "
            f"| {r.get('expected_severity', '')} "
            f"| {r.get('num_events', 0)} "
            f"| {r.get('total_packets', 0)} |"
        )
    lines.append("")

    # ── 3. Detection Metrics
    lines.append("## 3. Detection Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| True Positives (TP) | {metrics.get('true_positives', 0)} |")
    lines.append(f"| True Negatives (TN) | {metrics.get('true_negatives', 0)} |")
    lines.append(f"| False Positives (FP) | {metrics.get('false_positives', 0)} |")
    lines.append(f"| False Negatives (FN) | {metrics.get('false_negatives', 0)} |")
    lines.append(f"| Accuracy | {metrics.get('accuracy', 0):.4f} |")
    lines.append(f"| Detection Rate (Recall) | {metrics.get('detection_rate', 0):.4f} |")
    lines.append(f"| Precision | {metrics.get('precision', 0):.4f} |")
    lines.append(f"| F1 Score | {metrics.get('f1_score', 0):.4f} |")
    lines.append(f"| False Positive Rate | {metrics.get('false_positive_rate', 0):.4f} |")
    lines.append(f"| False Negative Rate | {metrics.get('false_negative_rate', 0):.4f} |")
    lines.append("")

    # ── 4. Detection Latency
    lines.append("## 4. Detection Latency")
    lines.append("")
    samples = timing.get("samples", 0)
    if samples > 0:
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Samples | {samples} |")
        lines.append(f"| Average | {timing.get('average_detection_time_ms', 'N/A')} ms |")
        lines.append(f"| Minimum | {timing.get('min_detection_time_ms', 'N/A')} ms |")
        lines.append(f"| Maximum | {timing.get('max_detection_time_ms', 'N/A')} ms |")
        lines.append(f"| Median | {timing.get('median_detection_time_ms', 'N/A')} ms |")
        lines.append(f"| Std Dev | {timing.get('stddev_detection_time_ms', 'N/A')} ms |")
    else:
        lines.append("*No detection events — latency measurement unavailable.*")
        lines.append("*(StubDetector produces no detections; connect Person 2's engine.)*")
    lines.append("")

    # ── 5. False Positive Analysis
    lines.append("## 5. False Positive Analysis")
    lines.append("")
    total_fp = fp.get("total_false_positives", 0)
    total_fn = fp.get("total_false_negatives", 0)
    lines.append(f"- **False positive scenarios:** {total_fp}")
    lines.append(f"- **False negative scenarios:** {total_fn}")
    lines.append("")
    if total_fp > 0:
        lines.append("### FP by Rule")
        lines.append("")
        for rule, count in fp.get("false_positives_by_rule", {}).items():
            lines.append(f"- `{rule}`: {count}")
        lines.append("")
    if total_fn > 0:
        lines.append("### FN by Expected Event Type")
        lines.append("")
        for et, count in fp.get("false_negatives_by_expected_type", {}).items():
            lines.append(f"- `{et}`: {count}")
        lines.append("")

    # ── 6. DDoS / Network Impact Analysis
    lines.append("## 6. DDoS / Network Impact Analysis")
    lines.append("")
    if ddos:
        tc = ddos.get("traffic_comparison", {})
        obs_list = tc.get("impact_summary", [])
        if obs_list:
            for obs in obs_list:
                lines.append(f"- {obs}")
            lines.append("")

        ds = ddos.get("detection_summary", {})
        lines.append(f"- **Total detection events:** {ds.get('total_events', 0)}")
        lines.append(f"- **Affected devices:** {ds.get('affected_device_count', 0)}")
        lines.append("")

        # Extended analysis
        ext = ddos.get("ddos_impact_analysis", {})
        if ext:
            lines.append("### Impact Metrics")
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| Normal ARP rate | {ext.get('normal_arp_rate', 'N/A')} pps |")
            lines.append(f"| Suspicious ARP rate | {ext.get('suspicious_arp_rate', 'N/A')} pps |")
            lines.append(f"| Rate increase | {ext.get('rate_increase_percent', 'N/A')}% |")
            lines.append(f"| Affected hosts | {ext.get('affected_hosts', 'N/A')} |")
            lines.append(f"| Suspicious events | {ext.get('suspicious_events', 'N/A')} |")
            lines.append(f"| Attack duration | {ext.get('attack_duration_seconds', 'N/A')} s |")
            lines.append(f"| Conflicting mappings | {ext.get('conflicting_mappings', 'N/A')} |")
            lines.append(f"| Pre-mitigation disruption | {ext.get('pre_mitigation_disruption', 'N/A')} |")
            lines.append(f"| Post-mitigation disruption | {ext.get('post_mitigation_disruption', 'N/A')} |")
            lines.append(f"| Improvement | {ext.get('improvement_percent', 'N/A')}% |")
            lines.append("")

        # Phase comparison
        phases = ddos.get("phase_comparison", {})
        if phases:
            lines.append("### Phase Comparison (Normal → Suspicious → Post-Mitigation)")
            lines.append("")
            lines.append("| Phase | ARP Rate (pps) | Suspicious Events | Affected Hosts | Disruption |")
            lines.append("|-------|----------------|-------------------|----------------|------------|")
            for phase_name in ["normal", "suspicious_activity", "post_mitigation"]:
                p = phases.get(phase_name, {})
                if "note" in p:
                    lines.append(f"| {phase_name} | — | — | — | {p['note']} |")
                else:
                    lines.append(
                        f"| {phase_name} "
                        f"| {p.get('arp_rate_pps', 'N/A')} "
                        f"| {p.get('suspicious_events', 'N/A')} "
                        f"| {p.get('affected_hosts', 'N/A')} "
                        f"| {p.get('disruption_indicator', 'N/A')} |"
                    )
            lines.append("")

        # Mitigation
        mit = ddos.get("mitigation", {})
        lines.append("### Mitigation Status")
        lines.append("")
        if mit.get("triggered"):
            lines.append(f"- **Triggered:** Yes")
            lines.append(f"- **Action:** {mit.get('action_taken', 'N/A')}")
            lines.append(f"- **Result:** {mit.get('result', 'N/A')}")
        else:
            lines.append(f"- **Triggered:** No")
            lines.append(f"- **Note:** {mit.get('note', 'Not available')}")
        lines.append("")
    else:
        lines.append("*DDoS impact data not available.*")
        lines.append("")

    # ── 7. Limitations
    lines.append("## 7. Limitations")
    lines.append("")
    for lim in full_report.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")

    # ── 8. Conclusions
    lines.append("## 8. Conclusions")
    lines.append("")
    for c in full_report.get("conclusions", []):
        lines.append(f"- {c}")
    lines.append("")

    lines.append("---")
    lines.append(f"*Report generated by ARPShield Testing & Evaluation Module (Person 3) v{full_report['report_metadata']['version']}*")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
