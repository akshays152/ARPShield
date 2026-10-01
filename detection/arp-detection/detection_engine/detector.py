from detection_engine.baseline_manager import BaselineManager
from detection_engine.arp_table import ARPTable
from detection_engine.rules import (
    conflict_rule, gateway_rule, baseline_rule, duplicate_rule,
    mac_change_rule, suspicious_reply_rule, rate_threshold_rule,
)
from detection_engine.rules.rate_threshold_rule import RateTracker


class DetectionContext:
    def __init__(self, baseline_path="config/trusted_baseline.json"):
        self.baseline = BaselineManager(baseline_path)
        self.arp_table = ARPTable()
        self.rate_tracker = RateTracker(window=1.0)


class ARPSpoofDetector:
    RULES = [
        gateway_rule.check,
        conflict_rule.check,
        baseline_rule.check,
        duplicate_rule.check,
        mac_change_rule.check,
        suspicious_reply_rule.check,
        rate_threshold_rule.check,
    ]

    def __init__(self, baseline_path="config/trusted_baseline.json"):
        self.ctx = DetectionContext(baseline_path)

    def process(self, packet):
        """
        packet: dict with keys
            timestamp, src_mac, src_ip, dst_mac, dst_ip, op
        Returns: list of alerts (may be empty)
        """
        # 1. Update state BEFORE running rules
        self.ctx.arp_table.update(packet["src_ip"], packet["src_mac"],
                                  packet.get("timestamp"))

        # 2. Run every rule
        alerts = []
        for rule in self.RULES:
            result = rule(packet, self.ctx)
            if result:
                alerts.append(result)
        return alerts