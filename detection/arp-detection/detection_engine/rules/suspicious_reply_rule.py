from detection_engine.alert_generator import make_alert
from detection_engine.severity import severity_for


def check(packet, ctx):
    # Gratuitous ARP: reply where src and dst IP are the same
    if packet["op"] == "reply" and packet.get("src_ip") == packet.get("dst_ip"):
        return make_alert(
            rule="gratuitous_arp",
            severity=severity_for("gratuitous_arp"),
            attacker_mac=packet["src_mac"],
            attacker_ip=packet["src_ip"],
            victim_ip=packet["dst_ip"],
            reason="Unsolicited (gratuitous) ARP reply detected",
            evidence=packet,
            recommended_action="monitor",
        )

    # Reply with broadcast destination MAC
    if packet["op"] == "reply" and packet.get("dst_mac") == "ff:ff:ff:ff:ff:ff":
        return make_alert(
            rule="suspicious_arp_reply",
            severity=severity_for("suspicious_arp_reply"),
            attacker_mac=packet["src_mac"],
            attacker_ip=packet["src_ip"],
            victim_ip=packet.get("dst_ip"),
            reason="ARP reply sent to broadcast MAC",
            evidence=packet,
            recommended_action="monitor",
        )
    return None