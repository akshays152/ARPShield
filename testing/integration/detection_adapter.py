"""
Detection Adapter — Abstract interface for Person 2's detection engine.

Person 3's testing module does NOT implement detection logic.
This adapter defines the contract that Person 2's detection engine
must satisfy so that the testing / evaluation pipeline can consume
detection results.

Usage for Person 2
------------------
Person 2 should subclass ``DetectionAdapter`` and implement:

    class MyDetector(DetectionAdapter):
        def analyze_packet(self, packet):
            ...  # your detection logic
            return [DetectionEvent(...), ...]

        def analyze_batch(self, packets):
            ...  # your batch logic
            return [DetectionEvent(...), ...]

        def get_statistics(self):
            return {"total_detections": ..., ...}

Then pass the adapter to the evaluation runner:

    from testing.run_evaluation import run_evaluation
    from testing.integration.detection_adapter import MyDetector

    results = run_evaluation(detector=MyDetector())


Stub Detector
-------------
When Person 2's engine is not yet connected, the ``StubDetector``
returns empty results for every packet.  This allows the testing
framework to run end-to-end and measure baseline (no-detection)
behaviour.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional


@dataclass
class DetectionEvent:
    """Standardised detection output expected from Person 2's engine.

    Person 2 may produce richer objects; this dataclass captures the
    minimum fields needed for evaluation.
    """
    event_type: str          # e.g. "IP_MAC_MAPPING_CHANGE", "GATEWAY_SPOOFING"
    severity: str            # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    reason: str              # Human-readable description
    affected_ip: str = ""
    affected_mac: str = ""
    timestamp: str = ""      # ISO-8601 string
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DetectionAdapter(ABC):
    """Abstract interface that Person 2's detection engine must implement."""

    @abstractmethod
    def analyze_packet(self, packet: Dict[str, Any]) -> List[DetectionEvent]:
        """Analyze a single ARP packet (Person 1's schema).

        Parameters
        ----------
        packet : dict
            Keys: timestamp, sender_ip, sender_mac, target_ip,
            target_mac, operation.

        Returns
        -------
        list[DetectionEvent]
            Zero or more detection events triggered by this packet.
        """
        ...

    @abstractmethod
    def analyze_batch(self, packets: List[Dict[str, Any]]) -> List[DetectionEvent]:
        """Analyze a batch of ARP packets.

        Parameters
        ----------
        packets : list[dict]
            List of packet dicts in Person 1's schema.

        Returns
        -------
        list[DetectionEvent]
            All detection events triggered across the batch.
        """
        ...

    @abstractmethod
    def get_statistics(self) -> Dict[str, Any]:
        """Return aggregate statistics from the detection engine.

        Expected keys (at minimum):
            - total_detections: int
            - by_severity: dict[str, int]
            - by_event_type: dict[str, int]
        """
        ...

    def reset(self) -> None:
        """Reset internal state between test scenarios (optional)."""
        pass


class StubDetector(DetectionAdapter):
    """No-op detector used when Person 2's engine is not connected.

    Returns no detections for any packet.  This allows the entire
    testing pipeline to execute and produce baseline reports.
    """

    def __init__(self):
        self._packet_count = 0

    def analyze_packet(self, packet: Dict[str, Any]) -> List[DetectionEvent]:
        self._packet_count += 1
        return []

    def analyze_batch(self, packets: List[Dict[str, Any]]) -> List[DetectionEvent]:
        self._packet_count += len(packets)
        return []

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total_detections": 0,
            "by_severity": {},
            "by_event_type": {},
            "packets_processed": self._packet_count,
            "detector": "StubDetector (Person 2 not connected)",
        }

    def reset(self) -> None:
        self._packet_count = 0


@dataclass
class MitigationResult:
    """Standardised mitigation output expected from Person 4's module.

    Person 4 should populate this and pass it to the evaluation runner
    when mitigation data is available.
    """
    triggered: bool = False
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    action_taken: str = ""
    result: str = ""
    devices_before: Optional[int] = None
    devices_after: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
