import uuid
import time


def make_alert(rule, severity, attacker_mac=None, attacker_ip=None,
               victim_ip=None, reason="", evidence=None,
               recommended_action=None):
    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "rule": rule,
        "severity": severity.label(),
        "attacker_mac": attacker_mac,
        "attacker_ip": attacker_ip,
        "victim_ip": victim_ip,
        "reason": reason,
        "evidence": evidence or {},
        "recommended_action": recommended_action,
    }