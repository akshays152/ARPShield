"""
Scenario C: Gateway Spoofing

An attacker sends ARP replies claiming to be the gateway (router)
with a forged MAC address.  This is one of the most critical ARP
spoofing attacks because it enables man-in-the-middle interception.
Person 2's detection engine should raise a CRITICAL alert.
"""

import random
from datetime import datetime, timedelta
from typing import Optional

from .base import (
    BaseScenario, ScenarioResult, make_packet,
    GATEWAY_IP, GATEWAY_MAC, NORMAL_HOSTS, BROADCAST_MAC,
)


def _random_mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))


class GatewaySpoofingScenario(BaseScenario):
    name = "gateway_spoofing"
    description = (
        "An attacker forges ARP replies claiming to be the network "
        "gateway with a malicious MAC address."
    )

    def generate(
        self,
        base_time: Optional[datetime] = None,
        seed: int = 42,
    ) -> ScenarioResult:
        rng = random.Random(seed)
        t = base_time or datetime.now()
        packets = []

        # Phase 1: legitimate gateway traffic (10 packets)
        for _ in range(10):
            t += timedelta(seconds=rng.uniform(1.0, 3.0))
            dst_ip = rng.choice(list(NORMAL_HOSTS.keys()))
            packets.append(make_packet(
                timestamp=t,
                sender_ip=GATEWAY_IP,
                sender_mac=GATEWAY_MAC,
                target_ip=dst_ip,
                target_mac=NORMAL_HOSTS[dst_ip],
                operation="reply",
                label="normal",
            ))

        # Phase 2: attacker claims to be the gateway with a fake MAC
        attacker_mac = _random_mac(rng)
        host_ips = list(NORMAL_HOSTS.keys())
        for _ in range(15):
            t += timedelta(seconds=rng.uniform(0.05, 0.3))
            dst_ip = rng.choice(host_ips)
            packets.append(make_packet(
                timestamp=t,
                sender_ip=GATEWAY_IP,
                sender_mac=attacker_mac,
                target_ip=dst_ip,
                target_mac=NORMAL_HOSTS[dst_ip],
                operation="reply",
                label="gateway_spoofing",
            ))

        return ScenarioResult(
            scenario_name=self.name,
            description=self.description,
            expected_detection=True,
            expected_severity="CRITICAL",
            expected_event_types=["GATEWAY_MAPPING_CHANGE"],
            packets=packets,
            is_attack=True,
            tags=["spoofing", "gateway", "critical", "true_positive"],
        )
