from detection_engine.alert_generator import make_alert
from detection_engine.severity import severity_for


def check(packet, ctx):
    ip, mac = packet["src_ip"], packet["src_mac"]
    trusted_mac = ctx.baseline.get_trusted_mac(ip)

    if trusted_mac and trusted_mac != mac:
        return make_alert(
            rule="baseline_violation",
            severity=severity_for("baseline_violation"),
            attacker_mac=mac,
            attacker_ip=ip,
            victim_ip=ip,
            reason=f"MAC {mac} does not match trusted baseline {trusted_mac} for IP {ip}",
            evidence={"trusted_mac": trusted_mac, "packet": packet},
            recommended_action="investigate_host",
        )
    return None