from detection_engine.alert_generator import make_alert
from detection_engine.severity import severity_for


def check(packet, ctx):
    ip, mac = packet["src_ip"], packet["src_mac"]

    if ctx.arp_table.has_conflict(ip):
        known_macs = ctx.arp_table.get_macs_for_ip(ip)
        if mac not in known_macs[:-1]:  # new MAC for known IP
            return make_alert(
                rule="ip_mac_conflict",
                severity=severity_for("ip_mac_conflict"),
                attacker_mac=mac,
                attacker_ip=ip,
                victim_ip=ip,
                reason=f"IP {ip} already mapped to {known_macs[:-1]}, now claimed by {mac}",
                evidence={"known_macs": known_macs, "packet": packet},
                recommended_action="investigate_host",
            )
    return None