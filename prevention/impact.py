"""Network disruption and mitigation impact measurement."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class ImpactResult:
    """Measured network impact before and after mitigation."""

    target: Dict[str, Optional[str]]
    arp_rate_before: float
    arp_rate_after: float
    suspicious_rate_before: float
    suspicious_rate_after: float
    affected_hosts_before: int
    affected_hosts_after: int
    arp_reduction_percent: float
    suspicious_reduction_percent: float
    affected_hosts_reduction: int
    mitigation_time_seconds: float
    recovery_verified: bool
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ImpactAnalyzer:
    """Calculate measurable effects of defensive mitigation."""

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def _reduction_percent(
        before: float,
        after: float,
    ) -> float:
        if before <= 0:
            return 0.0

        reduction = (
            (before - after) / before
        ) * 100.0

        return round(
            max(0.0, reduction),
            2,
        )

    def analyze(
        self,
        target: Dict[str, Optional[str]],
        arp_rate_before: float,
        arp_rate_after: float,
        suspicious_rate_before: float,
        suspicious_rate_after: float,
        affected_hosts_before: int,
        affected_hosts_after: int,
        mitigation_time_seconds: float,
        recovery_verified: bool,
    ) -> ImpactResult:
        """Compare network conditions before and after mitigation."""

        if arp_rate_before < 0 or arp_rate_after < 0:
            raise ValueError(
                "ARP traffic rates cannot be negative."
            )

        if (
            suspicious_rate_before < 0
            or suspicious_rate_after < 0
        ):
            raise ValueError(
                "Suspicious traffic rates cannot be negative."
            )

        if (
            affected_hosts_before < 0
            or affected_hosts_after < 0
        ):
            raise ValueError(
                "Affected host counts cannot be negative."
            )

        if mitigation_time_seconds < 0:
            raise ValueError(
                "Mitigation time cannot be negative."
            )

        return ImpactResult(
            target=dict(target),
            arp_rate_before=arp_rate_before,
            arp_rate_after=arp_rate_after,
            suspicious_rate_before=suspicious_rate_before,
            suspicious_rate_after=suspicious_rate_after,
            affected_hosts_before=affected_hosts_before,
            affected_hosts_after=affected_hosts_after,
            arp_reduction_percent=self._reduction_percent(
                arp_rate_before,
                arp_rate_after,
            ),
            suspicious_reduction_percent=self._reduction_percent(
                suspicious_rate_before,
                suspicious_rate_after,
            ),
            affected_hosts_reduction=(
                affected_hosts_before
                - affected_hosts_after
            ),
            mitigation_time_seconds=mitigation_time_seconds,
            recovery_verified=recovery_verified,
            timestamp=self._timestamp(),
        )