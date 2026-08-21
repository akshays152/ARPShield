"""Combine rule-based and ML signals into Low/Medium/High/Critical risk.

This module is defensive only. It does not generate ARP packets or perform
ARP spoofing. It consumes detection results produced by other modules.
"""

from dataclasses import dataclass, asdict
from typing import Any, Dict, List


RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Rule weights are intentionally explicit so the score is explainable.
RULE_WEIGHTS = {
    "mac_ip_change": 30,
    "ip_mac_conflict": 25,
    "unsolicited_reply": 20,
    "duplicate_ip": 20,
    "high_arp_rate": 10,
    "unknown_device": 10,
    "gateway_mapping_change": 35,
}


@dataclass
class RiskAssessment:
    score: float
    level: str
    rule_score: float
    ml_score: float
    rule_findings: List[str]
    ml_anomaly: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def rule_score(findings: Dict[str, Any]) -> tuple[float, List[str]]:
    """Convert rule-engine findings into a 0-100 score."""
    score = 0.0
    active = []

    for name, weight in RULE_WEIGHTS.items():
        value = findings.get(name, False)

        # Boolean findings contribute their complete weight.
        if isinstance(value, bool):
            if value:
                score += weight
                active.append(name)
            continue

        # Numeric findings are treated as confidence in [0, 1].
        if isinstance(value, (int, float)) and value > 0:
            contribution = weight * _clamp(float(value), 0, 1)
            score += contribution
            if contribution > 0:
                active.append(f"{name}={float(value):.2f}")

    return _clamp(score), active


def ml_risk_score(
    anomaly_score: float | None,
    is_anomaly: bool = False,
    normal_reference: float = 0.0,
    critical_reference: float = -0.5,
) -> float:
    """Map Isolation Forest's score to an explainable 0-100 risk score.

    Isolation Forest decision_function values are model-dependent. The
    mapping is therefore configurable rather than pretending the raw score
    is a percentage.
    """
    if anomaly_score is None:
        return 100.0 if is_anomaly else 0.0

    if anomaly_score >= normal_reference and not is_anomaly:
        return 0.0

    # More negative -> more anomalous.
    span = max(0.0001, normal_reference - critical_reference)
    score = ((normal_reference - float(anomaly_score)) / span) * 100.0

    # If the model explicitly marks the observation anomalous, do not let a
    # small negative score become zero.
    if is_anomaly:
        score = max(score, 50.0)

    return _clamp(score)


def _level(score: float) -> str:
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


def assess_risk(
    rule_findings: Dict[str, Any] | None = None,
    anomaly_score: float | None = None,
    is_anomaly: bool = False,
    trusted_device: bool = False,
) -> RiskAssessment:
    """Produce a combined defensive risk assessment.

    Default weighting:
      60% rule-based evidence
      40% ML anomaly evidence

    Trusted devices reduce the combined score by 10%, but never erase a
    strong critical rule finding. This is a prioritisation signal, not a
    security bypass.
    """
    findings = rule_findings or {}
    r_score, active = rule_score(findings)
    m_score = ml_risk_score(anomaly_score, is_anomaly)

    combined = (0.60 * r_score) + (0.40 * m_score)

    # If both independent systems agree, add a small correlation bonus.
    if active and is_anomaly:
        combined += 10

    if trusted_device:
        combined *= 0.90

    combined = _clamp(combined)
    level = _level(combined)

    explanation_parts = []
    if active:
        explanation_parts.append("Rule findings: " + ", ".join(active))
    if is_anomaly:
        explanation_parts.append("ML model marked the traffic window anomalous")
    elif anomaly_score is not None:
        explanation_parts.append(f"ML anomaly score={anomaly_score:.4f}")
    if trusted_device:
        explanation_parts.append("Trusted-device adjustment applied")
    if not explanation_parts:
        explanation_parts.append("No significant detection evidence")

    return RiskAssessment(
        score=round(combined, 2),
        level=level,
        rule_score=round(r_score, 2),
        ml_score=round(m_score, 2),
        rule_findings=active,
        ml_anomaly=is_anomaly,
        explanation="; ".join(explanation_parts),
    )
