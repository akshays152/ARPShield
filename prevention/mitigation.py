"""Controlled and reversible mitigation layer for ARPShield.

This module provides a safe abstraction for defensive containment.
The default implementation is a dry-run suitable for development and
authorized laboratory testing.

No destructive or permanent network changes are performed here.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class MitigationResult:
    """Result of a mitigation or recovery operation."""

    action: str
    status: str
    target: Dict[str, Optional[str]]
    timestamp: str
    message: str
    reversible: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MitigationController:
    """Execute controlled defensive actions.

    By default, actions are simulated. This allows the response pipeline
    to be tested without modifying the host network configuration.
    """

    SAFE_ACTIONS = {
        "ALERT_ADMIN",
        "MARK_DEVICE_UNTRUSTED",
        "ISOLATE_DEVICE",
    }

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.active_containments: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def _target_key(
        target: Dict[str, Optional[str]]
    ) -> str:
        mac = target.get("mac") or ""
        ip = target.get("ip") or ""
        return f"{mac.lower()}|{ip}"

    def apply(
        self,
        action: str,
        target: Dict[str, Optional[str]],
    ) -> MitigationResult:
        """Apply a controlled mitigation action."""

        if action not in self.SAFE_ACTIONS:
            raise ValueError(
                f"Unsupported mitigation action: {action}"
            )

        timestamp = self._timestamp()

        if action == "ALERT_ADMIN":
            return MitigationResult(
                action=action,
                status="COMPLETED",
                target=target,
                timestamp=timestamp,
                message="Administrator alert generated.",
            )

        if action == "MARK_DEVICE_UNTRUSTED":
            return MitigationResult(
                action=action,
                status="COMPLETED",
                target=target,
                timestamp=timestamp,
                message=(
                    "Device marked for untrusted handling."
                ),
            )

        # ISOLATE_DEVICE
        key = self._target_key(target)

        if self.dry_run:
            self.active_containments[key] = {
                "target": dict(target),
                "started_at": timestamp,
                "mode": "DRY_RUN",
            }

            return MitigationResult(
                action=action,
                status="COMPLETED",
                target=target,
                timestamp=timestamp,
                message=(
                    "Dry-run containment recorded; "
                    "no network configuration changed."
                ),
            )

        raise RuntimeError(
            "Live network containment is disabled in the "
            "current ARPShield mitigation controller."
        )

    def recover(
        self,
        target: Dict[str, Optional[str]],
    ) -> MitigationResult:
        """Recover a previously contained device."""

        key = self._target_key(target)
        timestamp = self._timestamp()

        if key not in self.active_containments:
            return MitigationResult(
                action="RECOVER_DEVICE",
                status="NOT_FOUND",
                target=target,
                timestamp=timestamp,
                message=(
                    "No active containment record exists "
                    "for this target."
                ),
            )

        del self.active_containments[key]

        return MitigationResult(
            action="RECOVER_DEVICE",
            status="RECOVERED",
            target=target,
            timestamp=timestamp,
            message=(
                "Containment record removed and the "
                "target marked as recovered."
            ),
        )

    def is_contained(
        self,
        target: Dict[str, Optional[str]],
    ) -> bool:
        """Check whether a target has an active containment record."""

        return (
            self._target_key(target)
            in self.active_containments
        )
    def monitor(
        self,
        target: Dict[str, Optional[str]],
        before_rate: float,
        after_rate: float,
        reduction_threshold: float = 20.0,
    ):
        """Evaluate traffic reduction after mitigation."""

        from prevention.monitoring import MitigationMonitor

        monitor = MitigationMonitor(
            reduction_threshold=reduction_threshold
        )

        return monitor.evaluate(
            target=target,
            before_rate=before_rate,
            after_rate=after_rate,
        )