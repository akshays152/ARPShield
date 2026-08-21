"""
Data models for ARP spoofing detection
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, List, Any
from enum import Enum
import uuid

class Severity(Enum):
    """Severity levels for detection events"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class EventType(Enum):
    """Types of detection events"""
    IP_MAC_MAPPING_CHANGE = "IP_MAC_MAPPING_CHANGE"
    DUPLICATE_IP_CLAIM = "DUPLICATE_IP_CLAIM"
    UNUSUAL_ARP_ACTIVITY = "UNUSUAL_ARP_ACTIVITY"
    GATEWAY_MAPPING_CHANGE = "GATEWAY_MAPPING_CHANGE"
    ARP_SPOOFING_ATTACK = "ARP_SPOOFING_ATTACK"
    SUSPICIOUS_ARP_RATE = "SUSPICIOUS_ARP_RATE"
    MAC_FLOODING = "MAC_FLOODING"
    ARP_REQUEST_STORM = "ARP_REQUEST_STORM"

class ARPOperation(Enum):
    """ARP operation types"""
    REQUEST = "request"
    REPLY = "reply"

@dataclass
class ARPPacket:
    """Represents an ARP packet with all relevant fields"""
    timestamp: datetime
    source_ip: str
    source_mac: str
    target_ip: str
    target_mac: Optional[str]
    operation: ARPOperation
    interface: str
    packet_size: int
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'source_mac': self.source_mac,
            'target_ip': self.target_ip,
            'target_mac': self.target_mac,
            'operation': self.operation.value,
            'interface': self.interface,
            'packet_size': self.packet_size
        }

@dataclass
class ARPMapping:
    """Maintains IP-MAC mapping with history"""
    ip: str
    current_mac: str
    first_seen: datetime
    last_seen: datetime
    mac_history: List[Dict[str, Any]] = field(default_factory=list)
    packet_count: int = 0
    reply_count: int = 0
    request_count: int = 0
    is_gateway: bool = False
    last_change_time: Optional[datetime] = None
    change_count: int = 0

@dataclass
class DetectionResult:
    """Structured detection output"""
    detection_id: str
    event_type: EventType
    severity: Severity
    reason: str
    affected_device: Dict[str, str]
    timestamp: datetime
    source_packet: Optional[ARPPacket] = None
    additional_info: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.detection_id:
            self.detection_id = f"detect_{datetime.now().timestamp()}_{uuid.uuid4().hex[:8]}"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'detection_id': self.detection_id,
            'event_type': self.event_type.value,
            'severity': self.severity.value,
            'reason': self.reason,
            'affected_device': self.affected_device,
            'timestamp': self.timestamp.isoformat(),
            'additional_info': self.additional_info
        }