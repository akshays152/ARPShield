"""
Scenario B: IP-MAC Mapping Conflict

An attacker changes the MAC address associated with a known IP,
causing IP-MAC mapping conflicts. Person 2's detection engine should
flag this as an IP_MAC_MAPPING_CHANGE or ARP_SPOOFING_ATTACK.
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


class IPMACConflictScenario(BaseScenario):
    name = "ip_mac_conflict"
    description = (
        "A previously known IP address suddenly appears with a different "
        "MAC address, simulating an ARP cache poisoning attempt."
    )

    def generate(
        self,
        base_time: Optional[datetime] = None,
        seed: int = 42,
    ) -> ScenarioResult:
        rng = random.Random(seed)
        t = base_time or datetime.now()
        packets = []

        victim_ip = "192.168.1.10"
        legitimate_mac = NORMAL_HOSTS[victim_ip]

        # Phase 1: establish a normal baseline (20 packets)
        for _ in range(20):
            t += timedelta(seconds=rng.uniform(0.5, 2.0))
            packets.append(make_packet(
                timestamp=t,
                sender_ip=victim_ip,
                sender_mac=legitimate_mac,
                target_ip=GATEWAY_IP,
                target_mac=BROADCAST_MAC,
                operation="request",
                label="normal",
            ))

        # Phase 2: attacker sends replies claiming victim's IP with fake MAC
        fake_mac = _random_mac(rng)
        for _ in range(15):
            t += timedelta(seconds=rng.uniform(0.1, 0.5))
            dst_ip = rng.choice(list(NORMAL_HOSTS.keys()))
            packets.append(make_packet(
                timestamp=t,
                sender_ip=victim_ip,
                sender_mac=fake_mac,
                target_ip=dst_ip,
                target_mac=NORMAL_HOSTS.get(dst_ip, BROADCAST_MAC),
                operation="reply",
                label="ip_mac_conflict",
            ))

        return ScenarioResult(
            scenario_name=self.name,
            description=self.description,
            expected_detection=True,
            expected_severity="MEDIUM",
            expected_event_types=["IP_MAC_MAPPING_CHANGE", "ARP_SPOOFING_ATTACK"],
            packets=packets,
            is_attack=True,
            tags=["spoofing", "ip_mac_conflict", "true_positive"],
        )
