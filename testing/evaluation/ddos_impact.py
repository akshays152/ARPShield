"""
DDoS Impact Analysis -- Cybersecurity analysis module.

Compares NORMAL vs ABNORMAL (spoofing/flooding) network conditions
to demonstrate how ARP spoofing can contribute to network disruption
and how early detection/mitigation reduces the impact.

Uses Person 1's packet schema: sender_ip, sender_mac, target_ip,
target_mac, operation, timestamp.

This module does NOT generate any real DDoS attack.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional


def _safe_ratio(a: int, b: int) -> float:
    return round(a / max(b, 1), 4)


def analyze_traffic_profile(
    packets: List[Dict[str, Any]],
    label: str = "unknown",
) -> Dict[str, Any]:
    """Compute traffic statistics for a set of ARP packets.

    Each packet dict uses Person 1's schema:
        timestamp, sender_ip, sender_mac, target_ip, target_mac, operation
    """
    if not packets:
        return {"label": label, "total_packets": 0}

    total = len(packets)
    requests = sum(1 for p in packets if p.get("operation") == "request")
    replies = total - requests
    unique_src_ips = len(set(p.get("sender_ip", "") for p in packets))
    unique_src_macs = len(set(p.get("sender_mac", "") for p in packets))
    unique_dst_ips = len(set(p.get("target_ip", "") for p in packets))

    # IP-MAC mapping diversity (how many unique MACs per IP)
    ip_mac_map: Dict[str, set] = {}
    for p in packets:
        ip = p.get("sender_ip", "")
        mac = p.get("sender_mac", "")
        ip_mac_map.setdefault(ip, set()).add(mac)

    conflicting_ips = sum(1 for macs in ip_mac_map.values() if len(macs) > 1)

    # Duration
    try:
        timestamps = sorted(p.get("timestamp", "") for p in packets)
        if isinstance(timestamps[0], str):
            ts_parsed = [datetime.fromisoformat(t) for t in timestamps]
        else:
            ts_parsed = timestamps
        duration_s = (ts_parsed[-1] - ts_parsed[0]).total_seconds()
    except Exception:
        duration_s = 0.0

    pps = total / max(duration_s, 0.001)  # packets per second

    return {
        "label": label,
        "total_packets": total,
        "requests": requests,
        "replies": replies,
        "request_reply_ratio": _safe_ratio(requests, replies) if replies else float("inf"),
        "unique_source_ips": unique_src_ips,
        "unique_source_macs": unique_src_macs,
        "unique_target_ips": unique_dst_ips,
        "conflicting_ip_mac_mappings": conflicting_ips,
        "duration_seconds": round(duration_s, 2),
        "packets_per_second": round(pps, 2),
    }


def compare_conditions(
    normal_profile: Dict[str, Any],
    abnormal_profile: Dict[str, Any],
) -> Dict[str, Any]:
    """Compare normal vs abnormal traffic profiles."""
    def _delta(key: str):
        n = normal_profile.get(key, 0)
        a = abnormal_profile.get(key, 0)
        if isinstance(n, (int, float)) and isinstance(a, (int, float)):
            return round(a - n, 4)
        return None

    return {
        "normal": normal_profile,
        "abnormal": abnormal_profile,
        "deltas": {
            "total_packets": _delta("total_packets"),
            "requests": _delta("requests"),
            "replies": _delta("replies"),
            "packets_per_second": _delta("packets_per_second"),
            "conflicting_ip_mac_mappings": _delta("conflicting_ip_mac_mappings"),
            "unique_source_macs": _delta("unique_source_macs"),
        },
        "impact_summary": _generate_impact_summary(normal_profile, abnormal_profile),
    }


def _generate_impact_summary(
    normal: Dict[str, Any],
    abnormal: Dict[str, Any],
) -> List[str]:
    """Generate human-readable impact observations."""
    observations = []

    n_pps = normal.get("packets_per_second", 0)
    a_pps = abnormal.get("packets_per_second", 0)
    if n_pps > 0 and a_pps > n_pps * 2:
        observations.append(
            f"ARP packet rate increased {a_pps / max(n_pps, 0.01):.1f}x "
            f"during abnormal conditions ({a_pps:.1f} vs {n_pps:.1f} pps)"
        )

    n_conflicts = normal.get("conflicting_ip_mac_mappings", 0)
    a_conflicts = abnormal.get("conflicting_ip_mac_mappings", 0)
    if a_conflicts > n_conflicts:
        observations.append(
            f"IP-MAC conflicts rose from {n_conflicts} to {a_conflicts} "
            f"during the attack, indicating active ARP spoofing"
        )

    n_macs = normal.get("unique_source_macs", 0)
    a_macs = abnormal.get("unique_source_macs", 0)
    if a_macs > n_macs * 1.5:
        observations.append(
            f"Number of unique source MACs increased from {n_macs} to "
            f"{a_macs}, suggesting forged MAC addresses on the network"
        )

    if not observations:
        observations.append("No significant traffic deviation observed")

    return observations


def build_ddos_impact_report(
    normal_packets: List[Dict[str, Any]],
    abnormal_packets: List[Dict[str, Any]],
    detection_events: List[Dict[str, Any]],
    detection_time_ms: Optional[float] = None,
    mitigation_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a complete DDoS / network-impact analysis report.

    Parameters
    ----------
    normal_packets : list
        Packet dicts from a normal traffic scenario (Person 1 schema).
    abnormal_packets : list
        Packet dicts from an attack / abnormal scenario (Person 1 schema).
    detection_events : list
        DetectionEvent.to_dict() entries from Person 2's adapter.
    detection_time_ms : float, optional
        Time in ms from first malicious packet to first detection.
    mitigation_data : dict, optional
        Person 4 MitigationResult.to_dict(), if available.
    """
    normal_profile = analyze_traffic_profile(normal_packets, "normal")
    abnormal_profile = analyze_traffic_profile(abnormal_packets, "abnormal")
    comparison = compare_conditions(normal_profile, abnormal_profile)

    # Classify detection events by severity
    severity_counts: Dict[str, int] = {}
    event_type_counts: Dict[str, int] = {}
    for e in detection_events:
        sev = e.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        et = e.get("event_type", "UNKNOWN")
        event_type_counts[et] = event_type_counts.get(et, 0) + 1

    # Affected devices
    affected_ips = set()
    affected_macs = set()
    for e in detection_events:
        if e.get("affected_ip"):
            affected_ips.add(e["affected_ip"])
        if e.get("affected_mac"):
            affected_macs.add(e["affected_mac"])

    report = {
        "traffic_comparison": comparison,
        "detection_summary": {
            "total_events": len(detection_events),
            "by_severity": severity_counts,
            "by_event_type": event_type_counts,
            "affected_ips": list(affected_ips),
            "affected_macs": list(affected_macs),
            "affected_device_count": len(affected_ips),
        },
        "detection_time_ms": detection_time_ms,
    }

    # Person 4 mitigation integration
    if mitigation_data:
        report["mitigation"] = mitigation_data
    else:
        report["mitigation"] = {
            "triggered": False,
            "note": "Person 4 mitigation data not available for this test run",
        }

    return report
