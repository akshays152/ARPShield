"""
ARPShield — Testing, Evaluation & DDoS Impact Analysis Module (Person 3)

This module provides:
  - Controlled test scenarios simulating various ARP spoofing patterns
  - Evaluation metrics for the rule-based detection system
  - Detection latency measurement
  - False-positive analysis
  - DDoS / network-impact analysis comparing normal vs abnormal conditions
  - Before / during / after mitigation comparison
  - Report generation in JSON, CSV, TXT, and Markdown formats
  - Evaluation chart generation (matplotlib)
  - A detection adapter interface for Person 2 to plug in
  - A mitigation data interface for Person 4 to plug in

All test data uses Person 1's packet schema:
    timestamp, sender_ip, sender_mac, target_ip, target_mac, operation, label

All testing is simulation/test-data based.  No offensive network
functionality is included.  Tests must be run only in an authorised,
isolated laboratory environment.

Important: ARP spoofing and DDoS are distinct attacks.  This module
evaluates the network disruption / availability impact associated with
suspicious ARP activity.
"""

__version__ = "2.0.0"
__author__ = "Person 3"

