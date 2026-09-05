"""
Scenario E: Suspicious / Unsolicited ARP Replies

An attacker sends unsolicited ARP replies that were not preceded
by a corresponding ARP request.  Combined with MAC changes, this
should trigger Person 2's IP_MAC_MAPPING_CHANGE or ARP_SPOOFING_ATTACK
rules.
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


class SuspiciousRepliesScenario(BaseScenario):
    name = "suspicious_replies"
    description = (
        "Unsolicited ARP replies with forged MAC addresses sent "
        "without any preceding ARP request."
    )

    def generate(
        self,
        base_time: Optional[datetime] = None,
        seed: int = 42,
    ) -> ScenarioResult:
        rng = random.Random(seed)
        t = base_time or datetime.now()
        packets = []

        # Phase 1: normal baseline
        host_ips = list(NORMAL_HOSTS.keys())
        for _ in range(15):
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
            ))

        # Phase 2: unsolicited replies with spoofed MAC
        spoofed_ip = rng.choice(host_ips)
        attacker_mac = _random_mac(rng)
        for _ in range(12):
            t += timedelta(seconds=rng.uniform(0.05, 0.4))
            dst_ip = rng.choice(host_ips)
            packets.append(make_packet(
                timestamp=t,
                sender_ip=spoofed_ip,
                sender_mac=attacker_mac,
                target_ip=dst_ip,
                target_mac=NORMAL_HOSTS[dst_ip],
                operation="reply",
            ))

        return ScenarioResult(
            scenario_name=self.name,
            description=self.description,
            expected_detection=True,
            expected_severity="MEDIUM",
            expected_event_types=["IP_MAC_MAPPING_CHANGE", "ARP_SPOOFING_ATTACK"],
            packets=packets,
            is_attack=True,
            tags=["unsolicited_reply", "spoofing", "true_positive"],
        )
