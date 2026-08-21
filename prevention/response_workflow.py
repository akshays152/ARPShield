"""Administrator-approved defensive response workflow.

No ARP spoofing or offensive packet generation is implemented here.
Responses are represented as safe actions and are only executed after
explicit administrator approval.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
from typing import Any, Callable, Dict


class ResponseStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"


@dataclass
class ResponseRequest:
    request_id: str
    incident_id: str
    action: str
    target: Dict[str, Any]
    reason: str
    status: ResponseStatus = ResponseStatus.PENDING
    created_at: str = ""
    approved_by: str | None = None
    executed_at: str | None = None
    result: str | None = None


SAFE_ACTIONS = {
    "ALERT_ADMIN",
    "MARK_DEVICE_UNTRUSTED",
    "ISOLATE_DEVICE",
    "REFRESH_ARP_BASELINE",
}


class ResponseWorkflow:
    def __init__(
        self,
        path: str = "prevention/response_requests.json",
        executor: Callable[[ResponseRequest], str] | None = None,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.executor = executor or self._dry_run_executor
        self.requests: dict[str, ResponseRequest] = self._load()

    def _load(self) -> dict[str, ResponseRequest]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text())
            return {
                k: ResponseRequest(
                    **{
                        **v,
                        "status": ResponseStatus(v["status"]),
                    }
                )
                for k, v in raw.items()
            }
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return {}

    def _save(self) -> None:
        self.path.write_text(
            json.dumps(
                {k: asdict(v) for k, v in self.requests.items()},
                indent=2,
                default=str,
            )
        )

    @staticmethod
    def _dry_run_executor(request: ResponseRequest) -> str:
        return f"DRY_RUN: {request.action} for {request.target}"

    def create_request(
        self,
        request_id: str,
        incident_id: str,
        action: str,
        target: Dict[str, Any],
        reason: str,
    ) -> ResponseRequest:
        action = action.upper()
        if action not in SAFE_ACTIONS:
            raise ValueError(f"Unsupported defensive action: {action}")

        request = ResponseRequest(
            request_id=request_id,
            incident_id=incident_id,
            action=action,
            target=target,
            reason=reason,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.requests[request_id] = request
        self._save()
        return request

    def approve(self, request_id: str, admin: str) -> ResponseRequest:
        request = self._require(request_id)
        if request.status != ResponseStatus.PENDING:
            raise ValueError("Only pending requests can be approved")
        request.status = ResponseStatus.APPROVED
        request.approved_by = admin
        self._save()
        return request

    def reject(self, request_id: str, admin: str) -> ResponseRequest:
        request = self._require(request_id)
        if request.status != ResponseStatus.PENDING:
            raise ValueError("Only pending requests can be rejected")
        request.status = ResponseStatus.REJECTED
        request.approved_by = admin
        self._save()
        return request

    def execute(self, request_id: str) -> ResponseRequest:
        request = self._require(request_id)
        if request.status != ResponseStatus.APPROVED:
            raise PermissionError("Administrator approval is required before execution")

        request.result = self.executor(request)
        request.status = ResponseStatus.EXECUTED
        request.executed_at = datetime.now(timezone.utc).isoformat()
        self._save()
        return request

    def _require(self, request_id: str) -> ResponseRequest:
        if request_id not in self.requests:
            raise KeyError(f"Unknown response request: {request_id}")
        return self.requests[request_id]
