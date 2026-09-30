"""
Scenario F: High ARP Rate / ARP Flooding

A single source sends ARP packets at an abnormally high rate,
mimicking an ARP request storm or ARP-based DDoS attempt.
Person 2's detection engine should flag UNUSUAL_ARP_ACTIVITY
or MAC_FLOODING.
"""

import random
from datetime import datetime, timedelta
from typing import Optional

from .base import (
    BaseScenario, ScenarioResult, make_packet,
    GATEWAY_IP, NORMAL_HOSTS, BROADCAST_MAC,
)


def _random_mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))


class HighARPRateScenario(BaseScenario):
    name = "high_arp_rate"
    description = (
        "A single MAC address sends ARP packets at an abnormally "
        "high rate, simulating an ARP flood / DDoS precursor."
    )

    def generate(
        self,
        base_time: Optional[datetime] = None,
        num_flood_packets: int = 120,
        seed: int = 42,
    ) -> ScenarioResult:
        rng = random.Random(seed)
        t = base_time or datetime.now()
        packets = []

        # Phase 1: brief normal baseline
        host_ips = list(NORMAL_HOSTS.keys())
        for _ in range(10):
            t += timedelta(seconds=rng.uniform(0.5, 2.0))
            src_ip = rng.choice(host_ips)
            src_mac = NORMAL_HOSTS[src_ip]
            packets.append(make_packet(
                timestamp=t,
                sender_ip=src_ip,
                sender_mac=src_mac,
                target_ip=GATEWAY_IP,
                target_mac=BROADCAST_MAC,
                operation="request",
                label="normal",
            ))

        # Phase 2: ARP flood -- rapid packets from a single attacker MAC
        attacker_mac = _random_mac(rng)
        attacker_ip = "192.168.1.200"
        for _ in range(num_flood_packets):
            t += timedelta(milliseconds=rng.uniform(5, 50))
            target_ip = f"192.168.1.{rng.randint(1, 254)}"
            packets.append(make_packet(
                timestamp=t,
                sender_ip=attacker_ip,
                sender_mac=attacker_mac,
                target_ip=target_ip,
                target_mac=BROADCAST_MAC,
                operation="request",
                label="high_arp_rate",
            ))

        return ScenarioResult(
            scenario_name=self.name,
            description=self.description,
            expected_detection=True,
            expected_severity="HIGH",
            expected_event_types=[
                "UNUSUAL_ARP_ACTIVITY",
                "MAC_FLOODING",
                "ARP_REQUEST_STORM",
            ],
            packets=packets,
            is_attack=True,
            tags=["flood", "ddos", "high_rate", "true_positive"],
        )
