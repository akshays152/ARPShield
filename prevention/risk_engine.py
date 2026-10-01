"""Explainable, rule-based risk assessment for the defensive response layer.

This module does not perform detection itself and does not use machine-learning
signals. It converts explicit rule findings into an auditable 0-100 score.

The authoritative event severity used by Person 4 comes from Person 2's
DetectionResult.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List


RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


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
    rule_findings: List[str]
    trusted_device: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _clamp(
    value: float,
    low: float = 0.0,
    high: float = 100.0,
) -> float:
    return max(low, min(high, value))


def rule_score(
    findings: Dict[str, Any] | None = None,
) -> tuple[float, List[str]]:
    """Convert explicit rule findings into an explainable 0-100 score."""

    findings = findings or {}

    score = 0.0
    active: List[str] = []

    for name, weight in RULE_WEIGHTS.items():
        value = findings.get(name, False)

        if isinstance(value, bool):
            if value:
                score += weight
                active.append(name)

        elif isinstance(value, (int, float)) and value > 0:
            contribution = weight * _clamp(
                float(value),
                0.0,
                1.0,
            )
            score += contribution
            active.append(f"{name}={float(value):.2f}")

    return _clamp(score), active


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
    trusted_device: bool = False,
) -> RiskAssessment:
    """Assess risk from rule evidence only.

    A trusted-device flag is recorded as context but never suppresses a
    positive finding or reduces its score. This prevents a stale trust record
    from becoming a security bypass.
    """

    score, active = rule_score(rule_findings)

    level = _level(score)

    if active:
        explanation = "Rule findings: " + ", ".join(active)
    else:
        explanation = "No significant rule findings"

    if trusted_device:
        explanation += "; device is present in trusted-device records"

    return RiskAssessment(
        score=round(score, 2),
        level=level,
        rule_score=round(score, 2),
        rule_findings=active,
        trusted_device=trusted_device,
        explanation=explanation,
    )