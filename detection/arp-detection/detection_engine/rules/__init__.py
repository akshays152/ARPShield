# detection_engine/rules/__init__.py
"""
ARP spoofing detection rules.
Each module exposes a `check(packet, ctx)` function
that returns an alert dict or None.
"""

from . import (
    conflict_rule,
    gateway_rule,
    baseline_rule,
    duplicate_rule,
    mac_change_rule,
    suspicious_reply_rule,
    rate_threshold_rule,
)

__all__ = [
    "conflict_rule",
    "gateway_rule",
    "baseline_rule",
    "duplicate_rule",
    "mac_change_rule",
    "suspicious_reply_rule",
    "rate_threshold_rule",
]