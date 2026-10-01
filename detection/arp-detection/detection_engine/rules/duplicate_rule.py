from detection_engine.alert_generator import make_alert
from detection_engine.severity import severity_for


def check(packet, ctx):
    ip, mac = packet["src_ip"], packet["src_mac"]
    alerts = []

    if ctx.arp_table.has_duplicate_claim(mac):
        ips = ctx.arp_table.get_ips_for_mac(mac)
        if len(set(ips)) > 1:
            alerts.append(make_alert(
                rule="duplicate_mac_claim",
                severity=severity_for("duplicate_mac_claim"),
                attacker_mac=mac,
                attacker_ip=ip,
                reason=f"MAC {mac} is claiming multiple IPs: {set(ips)}",
                evidence={"ips": list(set(ips)), "packet": packet},
                recommended_action="investigate_host",
            ))

    return alerts[0] if alerts else None