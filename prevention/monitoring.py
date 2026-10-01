"""Post-mitigation monitoring for ARPShield.

This module records simple before/after traffic observations so the
defensive layer can determine whether abnormal activity has decreased
after mitigation.

It does not capture packets itself. Packet collection remains the
responsibility of the network-monitoring layer.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class MonitoringResult:
    """Result of comparing traffic before and after mitigation."""

    target: Dict[str, Optional[str]]
    before_rate: float
    after_rate: float
    reduction_percent: float
    status: str
    timestamp: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MitigationMonitor:
    """Evaluate whether abnormal traffic decreased after mitigation."""

    def __init__(self, reduction_threshold: float = 20.0):
        if reduction_threshold < 0:
            raise ValueError(
                "reduction_threshold cannot be negative."
            )

        self.reduction_threshold = reduction_threshold

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def _calculate_reduction(
        before_rate: float,
        after_rate: float,
    ) -> float:
        if before_rate <= 0:
            return 0.0

        reduction = (
            (before_rate - after_rate)
            / before_rate
        ) * 100.0

        return round(
            max(0.0, reduction),
            2,
        )

    def evaluate(
        self,
        target: Dict[str, Optional[str]],
        before_rate: float,
        after_rate: float,
    ) -> MonitoringResult:
        """Compare abnormal traffic rates before and after mitigation."""

        if before_rate < 0 or after_rate < 0:
            raise ValueError(
                "Traffic rates cannot be negative."
            )

        reduction = self._calculate_reduction(
            before_rate,
            after_rate,
        )

        if reduction >= self.reduction_threshold:
            status = "IMPROVED"

            message = (
                "Abnormal traffic decreased sufficiently "
                "after mitigation."
            )
        else:
            status = "NOT_IMPROVED"

            message = (
                "Abnormal traffic did not decrease "
                "enough after mitigation."
            )

        return MonitoringResult(
            target=dict(target),
            before_rate=before_rate,
            after_rate=after_rate,
            reduction_percent=reduction,
            status=status,
            timestamp=self._timestamp(),
            message=message,
        )