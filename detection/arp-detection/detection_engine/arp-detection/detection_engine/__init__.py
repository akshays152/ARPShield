# detection_engine/__init__.py
"""
ARP Spoofing Detection Engine
Rule-based detection of ARP spoofing, gateway impersonation,
duplicate IP/MAC claims, MAC changes, suspicious ARP replies,
and ARP rate-based attacks.
"""

from .detector import ARPSpoofDetector, DetectionContext
from .baseline_manager import BaselineManager
from .arp_table import ARPTable
from .alert_generator import make_alert
from .severity import Severity, severity_for

__version__ = "1.0.0"

__all__ = [
    "ARPSpoofDetector",
    "DetectionContext",
    "BaselineManager",
    "ARPTable",
    "make_alert",
    "Severity",
    "severity_for",
]