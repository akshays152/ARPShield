"""
DDoS Impact Analysis -- Cybersecurity analysis module.

IMPORTANT DISTINCTION:
    ARP spoofing and DDoS are distinct attacks.  This module evaluates
    the *network disruption / availability impact* associated with
    suspicious ARP activity.  It does NOT claim that every ARP spoofing
    event is a DDoS attack.

Compares NORMAL vs ABNORMAL (spoofing/flooding) network conditions
to demonstrate how ARP spoofing can contribute to network disruption
and how early detection/mitigation reduces the impact.

Uses Person 1's packet schema: sender_ip, sender_mac, target_ip,
target_mac, operation, timestamp, label.

This module does NOT generate any real DDoS attack.
All results produced from synthetic test data are clearly labelled
as "controlled synthetic evaluation".
"""

from datetime import datetime
from typing import Dict, Any, List, Optional


def _safe_ratio(a: int, b: int) -> float:
    return round(a / max(b, 1), 4)


def _safe_divide(a: float, b: float, default: float = 0.0) -> float:
    """Safe division returning *default* when divisor is zero."""
    if b == 0:
        return default
    return a / b


def analyze_traffic_profile(
    packets: List[Dict[str, Any]],
    label: str = "unknown",
) -> Dict[str, Any]:
    """Compute traffic statistics for a set of ARP packets.

    Each packet dict uses Person 1's schema:
        timestamp, sender_ip, sender_mac, target_ip, target_mac, operation
    """
    if not packets:
        return {
            "label": label,
            "total_packets": 0,
            "requests": 0,
            "replies": 0,
            "request_reply_ratio": 0.0,
            "unique_source_ips": 0,
            "unique_source_macs": 0,
            "unique_target_ips": 0,
            "conflicting_ip_mac_mappings": 0,
            "duration_seconds": 0.0,
            "packets_per_second": 0.0,
        }

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


# ── NEW: Disruption indicator ─────────────────────────────────────────


def compute_disruption_indicator(profile: Dict[str, Any]) -> float:
    """Compute a 0.0–1.0 disruption score from a traffic profile.

    The score is a weighted combination of:
        - conflicting IP-MAC mappings    (40 %)
        - unusual packets-per-second     (30 %)
        - number of unique source MACs   (30 %)

    Higher values indicate more network disruption.
    This is a *relative* metric — not an absolute scale.
    """
    conflicts = profile.get("conflicting_ip_mac_mappings", 0)
    pps = profile.get("packets_per_second", 0)
    macs = profile.get("unique_source_macs", 0)

    # Normalise each factor to [0, 1] with soft-capped denominators
    conflict_score = min(conflicts / 5.0, 1.0)    # 5+ conflicts → 1.0
    pps_score = min(pps / 100.0, 1.0)             # 100+ pps → 1.0
    mac_score = min(macs / 20.0, 1.0)             # 20+ unique MACs → 1.0

    return round(0.4 * conflict_score + 0.3 * pps_score + 0.3 * mac_score, 4)


# ── NEW: analyze_ddos_impact (Step 8 requirement) ────────────────────


def analyze_ddos_impact(
    normal_data: List[Dict[str, Any]],
    suspicious_data: List[Dict[str, Any]],
    post_mitigation_data: Optional[List[Dict[str, Any]]] = None,
    detection_latency_ms: Optional[float] = None,
) -> Dict[str, Any]:
    """Deterministic DDoS/DoS impact evaluation.

    Compares normal traffic against suspicious activity (and optionally
    post-mitigation traffic) to quantify the network-disruption impact
    of ARP spoofing-related anomalies.

    Parameters
    ----------
    normal_data : list[dict]
        Packet dicts from normal (baseline) traffic.
    suspicious_data : list[dict]
        Packet dicts from suspicious / abnormal activity.
    post_mitigation_data : list[dict], optional
        Packet dicts captured after Person 4's mitigation (if available).
    detection_latency_ms : float, optional
        Average detection latency in milliseconds.

    Returns
    -------
    dict
        Structured impact analysis result.  Clearly labelled as
        *controlled synthetic evaluation* when inputs are synthetic.
    """
    normal_profile = analyze_traffic_profile(normal_data, "normal")
    suspicious_profile = analyze_traffic_profile(suspicious_data, "suspicious")

    normal_rate = normal_profile.get("packets_per_second", 0)
    suspicious_rate = suspicious_profile.get("packets_per_second", 0)
    rate_increase = _safe_divide(
        (suspicious_rate - normal_rate) * 100,
        max(normal_rate, 0.001),
    )

    # Affected hosts: unique sender IPs in suspicious traffic
    affected_ips = set(p.get("sender_ip", "") for p in suspicious_data)
    affected_macs = set(p.get("sender_mac", "") for p in suspicious_data)

    # Suspicious events count (packets labelled as non-normal)
    suspicious_events = sum(
        1 for p in suspicious_data
        if p.get("label", "normal") != "normal"
    )

    # Duration of abnormal activity
    attack_duration = suspicious_profile.get("duration_seconds", 0)

    # Conflicting mappings
    ip_mac_map: Dict[str, set] = {}
    for p in suspicious_data:
        ip = p.get("sender_ip", "")
        mac = p.get("sender_mac", "")
        ip_mac_map.setdefault(ip, set()).add(mac)
    conflicting_mappings = sum(
        1 for macs in ip_mac_map.values() if len(macs) > 1
    )

    # Disruption indicators
    pre_disruption = compute_disruption_indicator(suspicious_profile)

    result: Dict[str, Any] = {
        "data_source": "controlled synthetic evaluation",
        "normal_arp_rate": round(normal_rate, 2),
        "suspicious_arp_rate": round(suspicious_rate, 2),
        "rate_increase_percent": round(rate_increase, 2),
        "affected_hosts": len(affected_ips),
        "affected_ips": sorted(affected_ips),
        "affected_macs": sorted(affected_macs),
        "suspicious_events": suspicious_events,
        "attack_duration_seconds": round(attack_duration, 2),
        "detection_latency_ms": detection_latency_ms,
        "conflicting_mappings": conflicting_mappings,
        "pre_mitigation_disruption": pre_disruption,
        "post_mitigation_disruption": None,
        "improvement_percent": None,
    }

    # Post-mitigation comparison (Step 9)
    if post_mitigation_data is not None:
        post_profile = analyze_traffic_profile(post_mitigation_data, "post_mitigation")
        post_disruption = compute_disruption_indicator(post_profile)
        result["post_mitigation_disruption"] = post_disruption
        if pre_disruption > 0:
            improvement = ((pre_disruption - post_disruption) / pre_disruption) * 100
            result["improvement_percent"] = round(improvement, 2)
        else:
            result["improvement_percent"] = 0.0
        result["post_mitigation_profile"] = post_profile
    else:
        result["post_mitigation_note"] = (
            "Person 4 mitigation data not available for this evaluation."
        )

    return result


# ── NEW: compare_mitigation_phases (Step 9) ──────────────────────────


def compare_mitigation_phases(
    normal_data: List[Dict[str, Any]],
    suspicious_data: List[Dict[str, Any]],
    post_mitigation_data: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Compare ARP rate, suspicious events, affected hosts, and
    disruption across NORMAL → SUSPICIOUS → POST-MITIGATION phases.

    If post-mitigation data is unavailable (Person 4 has not supplied
    it yet), the comparison covers only the first two phases.
    """
    normal_profile = analyze_traffic_profile(normal_data, "normal")
    suspicious_profile = analyze_traffic_profile(suspicious_data, "suspicious")

    phases = {
        "normal": {
            "arp_rate_pps": normal_profile.get("packets_per_second", 0),
            "suspicious_events": 0,
            "affected_hosts": normal_profile.get("unique_source_ips", 0),
            "disruption_indicator": compute_disruption_indicator(normal_profile),
        },
        "suspicious_activity": {
            "arp_rate_pps": suspicious_profile.get("packets_per_second", 0),
            "suspicious_events": sum(
                1 for p in suspicious_data
                if p.get("label", "normal") != "normal"
            ),
            "affected_hosts": suspicious_profile.get("unique_source_ips", 0),
            "disruption_indicator": compute_disruption_indicator(suspicious_profile),
        },
    }

    if post_mitigation_data is not None:
        post_profile = analyze_traffic_profile(post_mitigation_data, "post_mitigation")
        phases["post_mitigation"] = {
            "arp_rate_pps": post_profile.get("packets_per_second", 0),
            "suspicious_events": sum(
                1 for p in post_mitigation_data
                if p.get("label", "normal") != "normal"
            ),
            "affected_hosts": post_profile.get("unique_source_ips", 0),
            "disruption_indicator": compute_disruption_indicator(post_profile),
        }
    else:
        phases["post_mitigation"] = {
            "note": "Person 4 mitigation data not yet available."
        }

    return phases


# ── Original build_ddos_impact_report (preserved) ────────────────────


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

    # Extended impact analysis via new function
    ddos_impact = analyze_ddos_impact(
        normal_data=normal_packets,
        suspicious_data=abnormal_packets,
        detection_latency_ms=detection_time_ms,
    )

    # Phase comparison
    phase_comparison = compare_mitigation_phases(
        normal_data=normal_packets,
        suspicious_data=abnormal_packets,
    )

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
        "ddos_impact_analysis": ddos_impact,
        "phase_comparison": phase_comparison,
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
