"""Person-4 defensive response service.

The service consumes DetectionResult objects produced by Person 2.

Detection severity remains authoritative. This layer decides what defensive
response should be requested, records the incident, and preserves the
administrator approval gate before any response can execute.
"""

from dataclasses import asdict
from typing import Any, Dict

from detection.src.detection_models import DetectionResult, Severity

from .incident_logger import IncidentLogger
from .mitigation import MitigationController
from .response_workflow import ResponseWorkflow
from .trusted_devices import TrustedDeviceStore


class RiskResponseService:
    def __init__(
        self,
        trusted_path: str = "prevention/trusted_devices.json",
        incident_path: str = "prevention/incidents.jsonl",
        response_path: str = "prevention/response_requests.json",
    ):
        self.trusted = TrustedDeviceStore(trusted_path)
        self.incidents = IncidentLogger(incident_path)

        self.mitigation = MitigationController(
            dry_run=True
        )

        self.responses = ResponseWorkflow(
            response_path,
            executor=self._execute_response,
        )

    @staticmethod
    def _response_action(
        severity: Severity,
    ) -> str | None:
        """Map detection severity to a safe defensive action."""

        if severity in {
            Severity.CRITICAL,
            Severity.HIGH,
        }:
            return "ISOLATE_DEVICE"

        if severity == Severity.MEDIUM:
            return "MARK_DEVICE_UNTRUSTED"

        if severity in {
            Severity.LOW,
            Severity.INFO,
        }:
            return "ALERT_ADMIN"

        return None

    def _execute_response(
        self,
        request,
    ) -> str:
        """Execute an approved defensive response."""

        result = self.mitigation.apply(
            action=request.action,
            target=request.target,
        )

        return result.message

    def process_detection(
        self,
        detection: DetectionResult,
    ) -> Dict[str, Any]:
        """Process one structured detection result from Person 2."""

        affected = dict(
            detection.affected_device or {}
        )

        device_mac = (
            affected.get("mac")
            or affected.get("source_mac")
        )

        device_ip = (
            affected.get("ip")
            or affected.get("source_ip")
        )

        trusted = False

        if device_mac:
            trusted = self.trusted.is_trusted(
                device_mac,
                device_ip,
            )

        incident = self.incidents.log(
            incident_type=detection.event_type.value,
            severity=detection.severity.value,
            details={
                "detection_id": detection.detection_id,
                "device_mac": device_mac,
                "device_ip": device_ip,
                "trusted_device": trusted,
                "reason": detection.reason,
                "event_type": detection.event_type.value,
                "additional_info": detection.additional_info,
            },
        )

        action = self._response_action(
            detection.severity
        )

        response = None

        if action:
            response = self.responses.create_request(
                request_id=(
                    f"resp-{len(self.responses.requests) + 1}"
                ),
                incident_id=incident["timestamp"],
                action=action,
                target={
                    "mac": device_mac,
                    "ip": device_ip,
                },
                reason=detection.reason,
            )

        return {
            "detection": detection.to_dict(),
            "incident": incident,
            "response_request": (
                asdict(response)
                if response
                else None
            ),
        }