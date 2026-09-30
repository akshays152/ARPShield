"""
Scenario A: Normal ARP Traffic

Generates legitimate ARP request/reply patterns with consistent
IP-MAC mappings, normal inter-packet timing, and standard broadcast
requests.  Person 2's detection engine should produce ZERO alerts
for this traffic.
"""

import random
from datetime import datetime, timedelta
from typing import Optional

from .base import (
    BaseScenario, ScenarioResult, make_packet,
    GATEWAY_IP, GATEWAY_MAC, NORMAL_HOSTS, ALL_HOSTS, BROADCAST_MAC,
)


class NormalARPScenario(BaseScenario):
    name = "normal_arp"
    description = (
        "Normal ARP traffic with consistent IP-MAC mappings, "
        "standard request/reply patterns, and reasonable timing."
    )

    def generate(
        self,
        base_time: Optional[datetime] = None,
        num_packets: int = 60,
        seed: int = 42,
    ) -> ScenarioResult:
        rng = random.Random(seed)
        t = base_time or datetime.now()
        packets = []
        host_ips = list(NORMAL_HOSTS.keys())

        for _ in range(num_packets):
            t += timedelta(seconds=rng.uniform(0.5, 4.0))
            event = rng.random()

            if event < 0.45:
                # ARP request: "who has <target>?"
                src_ip = rng.choice(host_ips)
                src_mac = NORMAL_HOSTS[src_ip]
                dst_ip = rng.choice(list(ALL_HOSTS.keys()))
                packets.append(make_packet(
                    timestamp=t,
                    sender_ip=src_ip,
                    sender_mac=src_mac,
                    target_ip=dst_ip,
                    target_mac=BROADCAST_MAC,
                    operation="request",
                ))
            elif event < 0.85:
                # ARP reply
                src_ip = rng.choice(list(ALL_HOSTS.keys()))
                src_mac = ALL_HOSTS[src_ip]
                dst_ip = rng.choice(host_ips)
                dst_mac = NORMAL_HOSTS[dst_ip]
                packets.append(make_packet(
                    timestamp=t,
                    sender_ip=src_ip,
                    sender_mac=src_mac,
                    target_ip=dst_ip,
                    target_mac=dst_mac,
                    operation="reply",
                ))
            else:
                # Gratuitous ARP (normal maintenance)
                src_ip = rng.choice(host_ips)
                src_mac = NORMAL_HOSTS[src_ip]
                packets.append(make_packet(
                    timestamp=t,
                    sender_ip=src_ip,
                    sender_mac=src_mac,
                    target_ip=src_ip,
                    target_mac=BROADCAST_MAC,
                    operation="reply",
                ))

        return ScenarioResult(
            scenario_name=self.name,
            description=self.description,
            expected_detection=False,
            expected_severity="NONE",
            expected_event_types=[],
            packets=packets,
            is_attack=False,
            tags=["normal", "baseline", "true_negative"],
        )
