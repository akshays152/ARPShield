"""
Evaluation Visualization — Chart generation for testing reports.

Generates matplotlib charts from evaluation data:
    1. Normal vs suspicious ARP rate
    2. Suspicious events by scenario
    3. Detection latency distribution
    4. Before vs after mitigation comparison

All charts are saved to the output directory and their paths
are returned for inclusion in reports.

Charts represent evaluation data only.  If the input data is
synthetic, the chart titles clearly indicate this.
"""

import os
from typing import Dict, Any, List, Optional

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend for headless rendering
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


# ── Theme configuration ──────────────────────────────────────────────

_COLORS = {
    "normal": "#4CAF50",        # green
    "suspicious": "#F44336",    # red
    "post_mitigation": "#2196F3",  # blue
    "neutral": "#9E9E9E",       # grey
    "accent": "#FF9800",        # orange
}

_CHART_STYLE = {
    "figure.facecolor": "#FAFAFA",
    "axes.facecolor": "#FFFFFF",
    "axes.edgecolor": "#BDBDBD",
    "axes.grid": True,
    "grid.alpha": 0.3,
    "font.size": 10,
}


def _apply_style():
    """Apply consistent chart styling."""
    if MATPLOTLIB_AVAILABLE:
        plt.rcParams.update(_CHART_STYLE)


def generate_charts(
    scenario_results: List[Dict[str, Any]],
    detection_metrics: Dict[str, Any],
    timing_metrics: Dict[str, Any],
    ddos_impact: Optional[Dict[str, Any]] = None,
    output_dir: str = "testing/results",
    is_synthetic: bool = True,
) -> Dict[str, str]:
    """Generate all evaluation charts.

    Parameters
    ----------
    scenario_results : list
        Per-scenario results from the evaluation runner.
    detection_metrics : dict
        Aggregate detection metrics (TP, TN, FP, FN, etc.).
    timing_metrics : dict
        Detection latency statistics.
    ddos_impact : dict, optional
        DDoS impact analysis results.
    output_dir : str
        Directory for chart output.
    is_synthetic : bool
        If True, chart titles note the data is synthetic.

    Returns
    -------
    dict
        Mapping of chart name to file path.
    """
    if not MATPLOTLIB_AVAILABLE:
        return {"error": "matplotlib not installed — charts skipped"}

    os.makedirs(output_dir, exist_ok=True)
    _apply_style()
    suffix = " (Synthetic Data)" if is_synthetic else ""
    paths = {}

    # 1. Normal vs suspicious ARP rate
    if ddos_impact:
        p = _chart_arp_rate_comparison(ddos_impact, output_dir, suffix)
        if p:
            paths["arp_rate_comparison"] = p

    # 2. Suspicious events by scenario
    p = _chart_events_by_scenario(scenario_results, output_dir, suffix)
    if p:
        paths["events_by_scenario"] = p

    # 3. Detection latency
    p = _chart_detection_latency(scenario_results, output_dir, suffix)
    if p:
        paths["detection_latency"] = p

    # 4. Before vs after mitigation
    if ddos_impact:
        p = _chart_mitigation_comparison(ddos_impact, output_dir, suffix)
        if p:
            paths["mitigation_comparison"] = p

    # 5. Confusion matrix
    p = _chart_confusion_matrix(detection_metrics, output_dir, suffix)
    if p:
        paths["confusion_matrix"] = p

    plt.close("all")
    return paths


def _chart_arp_rate_comparison(
    ddos_impact: Dict[str, Any],
    output_dir: str,
    suffix: str,
) -> Optional[str]:
    """Bar chart: Normal vs Suspicious ARP rate."""
    tc = ddos_impact.get("traffic_comparison", {})
    normal = tc.get("normal", {})
    abnormal = tc.get("abnormal", {})

    n_rate = normal.get("packets_per_second", 0)
    a_rate = abnormal.get("packets_per_second", 0)

    if n_rate == 0 and a_rate == 0:
        return None

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(
        ["Normal", "Suspicious"],
        [n_rate, a_rate],
        color=[_COLORS["normal"], _COLORS["suspicious"]],
        width=0.5,
        edgecolor="white",
    )

    # Value labels
    for bar, val in zip(bars, [n_rate, a_rate]):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(n_rate, a_rate) * 0.02,
            f"{val:.1f}",
            ha="center", va="bottom", fontweight="bold",
        )

    ax.set_ylabel("Packets per Second (pps)")
    ax.set_title(f"ARP Traffic Rate: Normal vs Suspicious{suffix}")
    fig.tight_layout()
    path = os.path.join(output_dir, "chart_arp_rate_comparison.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _chart_events_by_scenario(
    results: List[Dict[str, Any]],
    output_dir: str,
    suffix: str,
) -> Optional[str]:
    """Horizontal bar chart: detection events per scenario."""
    scenarios = [r["scenario_name"] for r in results]
    events = [r.get("num_events", 0) for r in results]
    is_attack = [r.get("is_attack", False) for r in results]

    if not scenarios:
        return None

    colors = [
        _COLORS["suspicious"] if a else _COLORS["normal"]
        for a in is_attack
    ]

    fig, ax = plt.subplots(figsize=(8, max(3, len(scenarios) * 0.5 + 1)))
    bars = ax.barh(scenarios, events, color=colors, edgecolor="white")

    for bar, val in zip(bars, events):
        ax.text(
            bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
            str(val), ha="left", va="center", fontsize=9,
        )

    ax.set_xlabel("Detection Events")
    ax.set_title(f"Detection Events by Scenario{suffix}")
    ax.invert_yaxis()
    fig.tight_layout()
    path = os.path.join(output_dir, "chart_events_by_scenario.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _chart_detection_latency(
    results: List[Dict[str, Any]],
    output_dir: str,
    suffix: str,
) -> Optional[str]:
    """Bar chart: detection latency per scenario."""
    detected = [
        r for r in results
        if r.get("actual_detected") and r.get("detection_latency_ms") is not None
    ]

    if not detected:
        return None

    scenarios = [r["scenario_name"] for r in detected]
    latencies = [r["detection_latency_ms"] for r in detected]

    fig, ax = plt.subplots(figsize=(8, max(3, len(scenarios) * 0.5 + 1)))
    bars = ax.barh(scenarios, latencies, color=_COLORS["accent"], edgecolor="white")

    for bar, val in zip(bars, latencies):
        ax.text(
            bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
            f"{val:.1f} ms", ha="left", va="center", fontsize=9,
        )

    ax.set_xlabel("Detection Latency (ms)")
    ax.set_title(f"Detection Latency by Scenario{suffix}")
    ax.invert_yaxis()
    fig.tight_layout()
    path = os.path.join(output_dir, "chart_detection_latency.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def _chart_mitigation_comparison(
    ddos_impact: Dict[str, Any],
    output_dir: str,
    suffix: str,
) -> Optional[str]:
    """Grouped bar chart: before vs after mitigation."""
    phases = ddos_impact.get("phase_comparison", {})
    if not phases:
        return None

    normal = phases.get("normal", {})
    suspicious = phases.get("suspicious_activity", {})
    post_mit = phases.get("post_mitigation", {})

    # If post-mitigation is just a note, skip
    if "note" in post_mit:
        # Still show normal vs suspicious
        labels = ["Normal", "Suspicious"]
        arp_rates = [
            normal.get("arp_rate_pps", 0),
            suspicious.get("arp_rate_pps", 0),
        ]
        disruptions = [
            normal.get("disruption_indicator", 0),
            suspicious.get("disruption_indicator", 0),
        ]
        bar_colors = [_COLORS["normal"], _COLORS["suspicious"]]
    else:
        labels = ["Normal", "Suspicious", "Post-Mitigation"]
        arp_rates = [
            normal.get("arp_rate_pps", 0),
            suspicious.get("arp_rate_pps", 0),
            post_mit.get("arp_rate_pps", 0),
        ]
        disruptions = [
            normal.get("disruption_indicator", 0),
            suspicious.get("disruption_indicator", 0),
            post_mit.get("disruption_indicator", 0),
        ]
        bar_colors = [_COLORS["normal"], _COLORS["suspicious"], _COLORS["post_mitigation"]]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # ARP rate
    bars1 = ax1.bar(labels, arp_rates, color=bar_colors, edgecolor="white")
    for bar, val in zip(bars1, arp_rates):
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(arp_rates) * 0.02,
            f"{val:.1f}",
            ha="center", va="bottom", fontsize=9,
        )
    ax1.set_ylabel("Packets per Second")
    ax1.set_title("ARP Rate by Phase")

    # Disruption indicator
    bars2 = ax2.bar(labels, disruptions, color=bar_colors, edgecolor="white")
    for bar, val in zip(bars2, disruptions):
        ax2.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(max(disruptions), 0.01) * 0.02,
            f"{val:.3f}",
            ha="center", va="bottom", fontsize=9,
        )
    ax2.set_ylabel("Disruption Score (0-1)")
    ax2.set_title("Disruption Indicator by Phase")

    fig.suptitle(f"Phase Comparison{suffix}", fontweight="bold", y=1.02)
    fig.tight_layout()
    path = os.path.join(output_dir, "chart_mitigation_comparison.png")
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


def _chart_confusion_matrix(
    metrics: Dict[str, Any],
    output_dir: str,
    suffix: str,
) -> Optional[str]:
    """Visual confusion matrix."""
    tp = metrics.get("true_positives", 0)
    tn = metrics.get("true_negatives", 0)
    fp = metrics.get("false_positives", 0)
    fn = metrics.get("false_negatives", 0)

    matrix = [[tp, fn], [fp, tn]]
    labels = [["TP", "FN"], ["FP", "TN"]]

    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(matrix, cmap="RdYlGn", aspect="auto")

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Detected", "Not Detected"])
    ax.set_yticklabels(["Attack", "Normal"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")

    for i in range(2):
        for j in range(2):
            ax.text(
                j, i, f"{labels[i][j]}\n{matrix[i][j]}",
                ha="center", va="center", fontsize=14, fontweight="bold",
                color="white" if matrix[i][j] > max(tp, tn, fp, fn) / 2 else "black",
            )

    ax.set_title(f"Confusion Matrix{suffix}")
    fig.tight_layout()
    path = os.path.join(output_dir, "chart_confusion_matrix.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path
