from dataclasses import dataclass, asdict
from typing import Optional
import json


@dataclass
class DetectionEvent:
    # --- Required (Person 3's contract) ---
    event_type: str
    severity: str
    reason: str
    affected_ip: str
    affected_mac: str
    timestamp: str

    # --- Recommended extras ---
    rule: str = ""
    source: str = "rule"              # "rule" | "ml"
    packet_id: int = -1
    packet_timestamp: Optional[str] = None
    detection_latency_ms: Optional[float] = None

    # --- Optional (ML only) ---
    confidence: Optional[float] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @staticmethod
    def from_dict(d: dict) -> "DetectionEvent":
        return DetectionEvent(**d)