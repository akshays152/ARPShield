"""
Base class and utilities for all test scenarios.

All scenarios produce packets in Person 1's schema:
    {timestamp, sender_ip, sender_mac, target_ip, target_mac, operation}

No detection logic is included — scenarios only define expected outcomes.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional


# ── Constants: simulated lab network ──────────────────────────────────
GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = "aa:bb:cc:dd:ee:01"

NORMAL_HOSTS = {
    "192.168.1.10": "00:11:22:33:44:10",
    "192.168.1.11": "00:11:22:33:44:11",
    "192.168.1.12": "00:11:22:33:44:12",
    "192.168.1.13": "00:11:22:33:44:13",
    "192.168.1.14": "00:11:22:33:44:14",
    "192.168.1.15": "00:11:22:33:44:15",
}

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

ALL_HOSTS = {GATEWAY_IP: GATEWAY_MAC, **NORMAL_HOSTS}


def make_packet(
    timestamp: datetime,
    sender_ip: str,
    sender_mac: str,
    target_ip: str,
    target_mac: str,
    operation: str,
    label: str = "normal",
) -> Dict[str, Any]:
    """Create a packet dict in Person 1's schema.

    Parameters
    ----------
    label : str
        Ground-truth label for evaluation (e.g. 'normal',
        'gateway_spoofing', 'ip_mac_conflict').  Not used by the
        detection engine — only consumed by evaluation metrics.
    """
    return {
        "timestamp": timestamp.isoformat(),
        "sender_ip": sender_ip,
        "sender_mac": sender_mac,
        "target_ip": target_ip,
        "target_mac": target_mac,
        "operation": operation,
        "label": label,
    }


@dataclass
class ScenarioResult:
    """Metadata returned by every test scenario."""
    scenario_name: str
    description: str
    expected_detection: bool
    expected_severity: str          # LOW / MEDIUM / HIGH / CRITICAL / NONE
    expected_event_types: List[str] = field(default_factory=list)
    packets: List[Dict[str, Any]] = field(default_factory=list)
    is_attack: bool = False
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_name": self.scenario_name,
            "description": self.description,
            "expected_detection": self.expected_detection,
            "expected_severity": self.expected_severity,
            "expected_event_types": self.expected_event_types,
            "packets": self.packets,
            "is_attack": self.is_attack,
            "tags": self.tags,
        }


class BaseScenario:
    """Abstract base for all test scenarios."""
    name: str = "base"
    description: str = ""

    def generate(self, base_time: Optional[datetime] = None) -> ScenarioResult:
        raise NotImplementedError
