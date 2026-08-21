"""
ARPShield Rule-Based Detection Module

A comprehensive rule-based detection system for identifying ARP spoofing attacks.
"""

from .detection_models import *
from .rule_engine import *
from .detection_manager import *

__version__ = "1.0.0"
__all__ = [
    'ARPPacket',
    'ARPMapping',
    'DetectionResult',
    'DetectionStatistics',
    'Severity',
    'EventType',
    'ARPOperation',
    'DetectionRule',
    'IPMACChangeRule',
    'DuplicateIPClaimRule',
    'GatewayChangeRule',
    'UnusualARPActivityRule',
    'ARPRequestStormRule',
    'RuleEngine',
    'DetectionManager'
]