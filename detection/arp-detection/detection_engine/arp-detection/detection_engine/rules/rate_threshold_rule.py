from collections import defaultdict, deque
import time
from detection_engine.alert_generator import make_alert
from detection_engine.severity import severity_for


class RateTracker:
    def __init__(self, window=1.0):
        self.window = window
        self.events = defaultdict(deque)  # mac -> deque of timestamps

    def add(self, mac, ts=None):
        ts = ts or time.time()
        dq = self.events[mac]
        dq.append(ts)
        while dq and ts - dq[0] > self.window:
            dq.popleft()
        return len(dq)


THRESHOLDS = [
    (500, "rate_threshold_critical"),
    (200, "rate_threshold_high"),
    (50,  "rate_threshold_low"),
]


def check(packet, ctx):
    count = ctx.rate_tracker.add(packet["src_mac"])
    for threshold, rule in THRESHOLDS:
        if count > threshold:
            return make_alert(
                rule=rule,
                severity=severity_for(rule),
                attacker_mac=packet["src_mac"],
                attacker_ip=packet["src_ip"],
                reason=f"ARP packet rate {count}/s exceeds {threshold}/s",
                evidence={"count": count, "window": ctx.rate_tracker.window},
                recommended_action="rate_limit",
            )
    return None