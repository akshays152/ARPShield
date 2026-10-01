"""
Synthetic ARP traffic generator for ARPShield testing.

Outputs JSON-compatible packet dicts for scenarios 1-7.
Person 3's testing framework consumes these directly.
"""

from datetime import datetime, timedelta, timezone
import argparse
import json


# ---------- Time helper ----------
_BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def now_iso(offset: float = 0.0) -> str:
    return (_BASE + timedelta(seconds=offset)).isoformat()


# ---------- Packet builder ----------
def make_arp_packet(
    op: str,
    src_mac: str,
    src_ip: str,
    dst_mac: str,
    dst_ip: str,
    timestamp: str,
    packet_id: int,
    gratuitous: bool = False,
) -> dict:
    return {
        "packet_id": packet_id,
        "timestamp": timestamp,
        "protocol": "ARP",
        "op": op,
        "src_mac": src_mac,
        "src_ip": src_ip,
        "dst_mac": dst_mac,
        "dst_ip": dst_ip,
        "gratuitous": gratuitous,
    }


# ---------- Scenario 1: Normal ARP ----------
def scenario_1_normal_traffic(n: int = 50) -> list[dict]:
    packets = []
    for i in range(n):
        packets.append(make_arp_packet(
            op="request",
            src_mac="aa:bb:cc:00:00:01",
            src_ip="192.168.1.10",
            dst_mac="ff:ff:ff:ff:ff:ff",
            dst_ip="192.168.1.1",
            timestamp=now_iso(i * 0.1),
            packet_id=i,
        ))
    return packets


# ---------- Scenario 2: IP-MAC conflict ----------
def scenario_2_ip_mac_conflict() -> list[dict]:
    return [
        make_arp_packet("reply", "aa:bb:cc:00:00:01", "192.168.1.50",
                        "aa:bb:cc:00:00:99", "192.168.1.1", now_iso(0), 0),
        make_arp_packet("reply", "aa:bb:cc:00:00:02", "192.168.1.50",
                        "aa:bb:cc:00:00:99", "192.168.1.1", now_iso(0.5), 1),
    ]


# ---------- Scenario 3: Gateway spoof ----------
def scenario_3_gateway_spoof() -> list[dict]:
    return [
        make_arp_packet("reply", "aa:bb:cc:00:00:99", "192.168.1.1",
                        "aa:bb:cc:00:00:01", "192.168.1.50", now_iso(0), 0),
        make_arp_packet("reply", "de:ad:be:ef:00:01", "192.168.1.1",
                        "aa:bb:cc:00:00:01", "192.168.1.50", now_iso(1), 1),
    ]


# ---------- Scenario 4: ARP flood ----------
def scenario_4_arp_flood(pps: int = 50, duration_s: float = 2.0) -> list[dict]:
    total = int(pps * duration_s)
    interval = 1.0 / pps
    return [
        make_arp_packet(
            "reply",
            f"aa:bb:cc:00:00:{i % 256:02x}",
            "192.168.1.1",
            "ff:ff:ff:ff:ff:ff",
            "192.168.1.1",
            now_iso(i * interval),
            i,
        )
        for i in range(total)
    ]


# ---------- Scenario 5: MAC change ----------
def scenario_5_mac_change() -> list[dict]:
    return [
        make_arp_packet("reply", "aa:bb:cc:00:00:20", "192.168.1.20",
                        "aa:bb:cc:00:00:99", "192.168.1.1", now_iso(0), 0),
        make_arp_packet("reply", "aa:bb:cc:00:00:21", "192.168.1.20",
                        "aa:bb:cc:00:00:99", "192.168.1.1", now_iso(1), 1),
    ]


# ---------- Scenario 6: Duplicate IP ----------
def scenario_6_duplicate_ip() -> list[dict]:
    return [
        make_arp_packet("reply", "aa:bb:cc:00:00:30", "192.168.1.30",
                        "aa:bb:cc:00:00:99", "192.168.1.1", now_iso(0), 0),
        make_arp_packet("reply", "aa:bb:cc:00:00:31", "192.168.1.30",
                        "aa:bb:cc:00:00:99", "192.168.1.1", now_iso(0.5), 1),
    ]


# ---------- Scenario 7: Gratuitous ARP ----------
def scenario_7_gratuitous_arp() -> list[dict]:
    return [
        make_arp_packet("reply", "de:ad:be:ef:ff:ff", "192.168.1.100",
                        "ff:ff:ff:ff:ff:ff", "192.168.1.100",
                        now_iso(0), 0, gratuitous=True),
    ]


# ---------- CLI entry point ----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic ARP traffic.")
    parser.add_argument("--scenario", type=int, required=True, choices=range(1, 8))
    parser.add_argument("--out", type=str, default="packets.json")
    parser.add_argument("--pps", type=int, default=50, help="For scenario 4")
    parser.add_argument("--duration", type=float, default=2.0, help="For scenario 4")
    args = parser.parse_args()

    generators = {
        1: scenario_1_normal_traffic,
        2: scenario_2_ip_mac_conflict,
        3: scenario_3_gateway_spoof,
        4: lambda: scenario_4_arp_flood(args.pps, args.duration),
        5: scenario_5_mac_change,
        6: scenario_6_duplicate_ip,
        7: scenario_7_gratuitous_arp,
    }

    packets = generators[args.scenario]()
    with open(args.out, "w") as f:
        json.dump(packets, f, indent=2)
    print(f"Wrote {len(packets)} packets to {args.out}")