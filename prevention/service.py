"""High-level Person-4 service tying risk, trust, incidents and response together."""

from dataclasses import asdict
from typing import Any, Dict

from .incident_logger import IncidentLogger
from .response_workflow import ResponseWorkflow
from .risk_engine import assess_risk
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
        self.responses = ResponseWorkflow(response_path)

    def process_event(
        self,
        device_mac: str,
        device_ip: str | None,
        rule_findings: Dict[str, Any] | None = None,
        anomaly_score: float | None = None,
        is_anomaly: bool = False,
    ) -> Dict[str, Any]:
        trusted = self.trusted.is_trusted(device_mac, device_ip)

        assessment = assess_risk(
            rule_findings=rule_findings,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            trusted_device=trusted,
        )

        incident = self.incidents.log(
            incident_type="ARP_ANOMALY",
            severity=assessment.level,
            details={
                "device_mac": device_mac,
                "device_ip": device_ip,
                "trusted_device": trusted,
                "risk": assessment.to_dict(),
            },
        )

        response = None
        if assessment.level in {"HIGH", "CRITICAL"}:
            response = self.responses.create_request(
                request_id=f"resp-{len(self.responses.requests) + 1}",
                incident_id=incident["timestamp"],
                action="ISOLATE_DEVICE",
                target={"mac": device_mac, "ip": device_ip},
                reason=assessment.explanation,
            )

        return {
            "risk": assessment.to_dict(),
            "incident": incident,
            "response_request": asdict(response) if response else None,
        }
