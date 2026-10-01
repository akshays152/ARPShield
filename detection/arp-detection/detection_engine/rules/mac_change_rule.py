from detection_engine.alert_generator import make_alert
from detection_engine.severity import severity_for


def check(packet, ctx):
    ip = packet["src_ip"]
    if ctx.arp_table.mac_changed(ip):
        return make_alert(
            rule="mac_change",
            severity=severity_for("mac_change"),
            attacker_mac=packet["src_mac"],
            attacker_ip=ip,
            victim_ip=ip,
            reason=f"MAC for IP {ip} changed within the last {ctx.arp_table.mac_change_window}s",
            evidence=packet,
            recommended_action="investigate_host",
        )
    return None