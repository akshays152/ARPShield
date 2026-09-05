"""
ARPShield — Testing, Evaluation & DDoS Impact Analysis Module (Person 3)

This module provides:
  - Controlled test scenarios simulating various ARP spoofing patterns
  - Evaluation metrics for the rule-based detection system
  - DDoS / network-impact analysis comparing normal vs abnormal conditions
  - Report generation in JSON, CSV, and human-readable formats
  - A detection adapter interface for Person 2 to plug in

All test data uses Person 1's packet schema:
    timestamp, sender_ip, sender_mac, target_ip, target_mac, operation

All testing is simulation/test-data based.  No offensive network
functionality is included.  Tests must be run only in an authorised,
isolated laboratory environment.
"""

__version__ = "1.0.0"
__author__ = "Person 3"
