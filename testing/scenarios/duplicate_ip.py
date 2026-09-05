"""
Scenario D: Duplicate IP Claims

Multiple different MAC addresses claim the same IP address within
a short time window, indicating either a misconfigured network or
an active ARP spoofing attack.
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


class DuplicateIPScenario(BaseScenario):
    name = "duplicate_ip"
    description = (
        "Multiple different MAC addresses claim the same IP address, "
        "which should trigger DUPLICATE_IP_CLAIM detection."
    )

    def generate(
        self,
        base_time: Optional[datetime] = None,
        num_claimants: int = 6,
        seed: int = 42,
    ) -> ScenarioResult:
        rng = random.Random(seed)
        t = base_time or datetime.now()
        packets = []

        target_ip = "192.168.1.50"

        # Phase 1: brief normal baseline
        legit_mac = NORMAL_HOSTS.get("192.168.1.10", "00:11:22:33:44:10")
        for _ in range(5):
            t += timedelta(seconds=rng.uniform(0.5, 2.0))
            packets.append(make_packet(
                timestamp=t,
                sender_ip="192.168.1.10",
                sender_mac=legit_mac,
                target_ip=GATEWAY_IP,
                target_mac=BROADCAST_MAC,
                operation="request",
            ))

        # Phase 2: many MACs claim the same IP
        for i in range(num_claimants):
            t += timedelta(seconds=rng.uniform(0.05, 0.3))
            fake_mac = _random_mac(rng)
            packets.append(make_packet(
                timestamp=t,
                sender_ip=target_ip,
                sender_mac=fake_mac,
                target_ip=GATEWAY_IP,
                target_mac=BROADCAST_MAC,
                operation="request",
            ))

        return ScenarioResult(
            scenario_name=self.name,
            description=self.description,
            expected_detection=True,
            expected_severity="HIGH",
            expected_event_types=["DUPLICATE_IP_CLAIM"],
            packets=packets,
            is_attack=True,
            tags=["duplicate_ip", "true_positive"],
        )
