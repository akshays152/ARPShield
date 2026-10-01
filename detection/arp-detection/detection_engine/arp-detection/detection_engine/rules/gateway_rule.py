from detection_engine.alert_generator import make_alert
from detection_engine.severity import severity_for


def check(packet, ctx):
    if packet["op"] != "reply":
        return None

    if ctx.baseline.is_gateway_ip(packet["src_ip"]):
        if not ctx.baseline.is_gateway_mac(packet["src_mac"]):
            return make_alert(
                rule="gateway_impersonation",
                severity=severity_for("gateway_impersonation"),
                attacker_mac=packet["src_mac"],
                attacker_ip=packet["src_ip"],
                victim_ip=ctx.baseline.gateway_ip,
                reason="Non-gateway MAC claimed gateway IP in ARP reply",
                evidence=packet,
                recommended_action="block_mac",
            )
    return None