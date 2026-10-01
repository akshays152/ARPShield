from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self):
        return self.name.capitalize()


RULE_SEVERITY = {
    "ip_mac_conflict":        Severity.HIGH,
    "baseline_violation":     Severity.HIGH,
    "gateway_impersonation":  Severity.CRITICAL,
    "duplicate_ip_claim":     Severity.MEDIUM,
    "duplicate_mac_claim":    Severity.MEDIUM,
    "mac_change":             Severity.MEDIUM,
    "suspicious_arp_reply":   Severity.LOW,
    "gratuitous_arp":         Severity.LOW,
    "rate_threshold_low":     Severity.MEDIUM,
    "rate_threshold_high":    Severity.HIGH,
    "rate_threshold_critical": Severity.CRITICAL,
}


def severity_for(rule_name):
    return RULE_SEVERITY.get(rule_name, Severity.LOW)