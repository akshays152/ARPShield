"""
ARPShield — Synthetic ARP Data Generator
=========================================
Generates synthetic ARP packet observations for ML pipeline validation.

WARNING: This data is SYNTHETIC and generated solely for pipeline development
and testing. It does NOT represent real network traffic. Do NOT use any model
trained on this data to make production security decisions.

The generated data simulates what the network monitoring module (network/)
would produce once implemented. It follows the data contract defined in
the ML module documentation.

Expected data contract (per-packet ARP observation):
    - timestamp:  float (Unix epoch seconds)
    - op:         int (1 = ARP request, 2 = ARP reply)
    - src_mac:    string (source MAC address)
    - dst_mac:    string (destination MAC address)
    - src_ip:     string (sender IP address)
    - dst_ip:     string (target IP address)

Usage:
    python ml/generate_sample_data.py [--output PATH] [--num-normal N] [--num-anomalous N]
"""

import argparse
import csv
import os
import random
import time


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Simulated "normal" network: a /24 subnet with a gateway
GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = "aa:bb:cc:dd:ee:01"

# Normal hosts on the network
NORMAL_HOSTS = {
    "192.168.1.10": "00:11:22:33:44:10",
    "192.168.1.11": "00:11:22:33:44:11",
    "192.168.1.12": "00:11:22:33:44:12",
    "192.168.1.13": "00:11:22:33:44:13",
    "192.168.1.14": "00:11:22:33:44:14",
    "192.168.1.15": "00:11:22:33:44:15",
    "192.168.1.20": "00:11:22:33:44:20",
    "192.168.1.21": "00:11:22:33:44:21",
}

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# All hosts including gateway
ALL_HOSTS = {GATEWAY_IP: GATEWAY_MAC, **NORMAL_HOSTS}


def _random_mac():
    """Generate a random MAC address."""
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def generate_normal_traffic(base_time: float, num_packets: int) -> list[dict]:
    """
    Generate normal ARP traffic patterns.

    Normal patterns include:
    - Hosts sending ARP requests (op=1) to resolve IPs, with broadcast dst_mac
    - Corresponding ARP replies (op=2) from the target host
    - Occasional gratuitous ARP (src_ip == dst_ip)
    - Reasonable inter-packet timing (0.5s - 5s gaps)
    """
    packets = []
    current_time = base_time
    host_ips = list(NORMAL_HOSTS.keys())

    for _ in range(num_packets):
        current_time += random.uniform(0.5, 5.0)
        event_type = random.random()

        if event_type < 0.45:
            # ARP Request: host asks "who has <target_ip>?"
            src_ip = random.choice(host_ips)
            src_mac = NORMAL_HOSTS[src_ip]
            dst_ip = random.choice(list(ALL_HOSTS.keys()))
            # ARP requests are broadcast
            packets.append({
                "timestamp": round(current_time, 6),
                "op": 1,
                "src_mac": src_mac,
                "dst_mac": BROADCAST_MAC,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            })
        elif event_type < 0.85:
            # ARP Reply: host responds with its MAC
            src_ip = random.choice(list(ALL_HOSTS.keys()))
            src_mac = ALL_HOSTS[src_ip]
            dst_ip = random.choice(host_ips)
            dst_mac = NORMAL_HOSTS[dst_ip]
            packets.append({
                "timestamp": round(current_time, 6),
                "op": 2,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            })
        else:
            # Gratuitous ARP (normal maintenance): host announces itself
            src_ip = random.choice(host_ips)
            src_mac = NORMAL_HOSTS[src_ip]
            packets.append({
                "timestamp": round(current_time, 6),
                "op": 2,
                "src_mac": src_mac,
                "dst_mac": BROADCAST_MAC,
                "src_ip": src_ip,
                "dst_ip": src_ip,
            })

    return packets


def generate_anomalous_traffic(base_time: float, num_packets: int) -> list[dict]:
    """
    Generate anomalous ARP traffic patterns that simulate suspicious behaviour.

    Anomalous patterns include:
    - ARP reply floods (many replies in rapid succession)
    - MAC spoofing (different MAC claiming an existing IP)
    - Rapid scanning (many requests to different IPs)
    - Unsolicited replies (replies without preceding requests)

    NOTE: These are simplified simulations for pipeline validation only.
    """
    packets = []
    current_time = base_time
    anomaly_types = ["reply_flood", "mac_spoof", "scan", "unsolicited"]

    for _ in range(num_packets):
        anomaly = random.choice(anomaly_types)

        if anomaly == "reply_flood":
            # Rapid burst of ARP replies from a single MAC
            attacker_mac = _random_mac()
            attacker_ip = random.choice(list(NORMAL_HOSTS.keys()))
            for _ in range(random.randint(5, 15)):
                current_time += random.uniform(0.01, 0.1)  # Very rapid
                target_ip = random.choice(list(NORMAL_HOSTS.keys()))
                target_mac = NORMAL_HOSTS[target_ip]
                packets.append({
                    "timestamp": round(current_time, 6),
                    "op": 2,
                    "src_mac": attacker_mac,
                    "dst_mac": target_mac,
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                })

        elif anomaly == "mac_spoof":
            # A new/random MAC claims an existing host's IP (or gateway IP)
            spoofed_ip = random.choice([GATEWAY_IP] + list(NORMAL_HOSTS.keys()))
            fake_mac = _random_mac()
            current_time += random.uniform(0.05, 0.5)
            for target_ip, target_mac in list(NORMAL_HOSTS.items())[:3]:
                current_time += random.uniform(0.02, 0.1)
                packets.append({
                    "timestamp": round(current_time, 6),
                    "op": 2,
                    "src_mac": fake_mac,
                    "dst_mac": target_mac,
                    "src_ip": spoofed_ip,
                    "dst_ip": target_ip,
                })

        elif anomaly == "scan":
            # Rapid ARP requests to many sequential IPs (network scanning)
            scanner_ip = "192.168.1.100"
            scanner_mac = _random_mac()
            for i in range(random.randint(10, 30)):
                current_time += random.uniform(0.01, 0.05)
                target_ip = f"192.168.1.{random.randint(1, 254)}"
                packets.append({
                    "timestamp": round(current_time, 6),
                    "op": 1,
                    "src_mac": scanner_mac,
                    "dst_mac": BROADCAST_MAC,
                    "src_ip": scanner_ip,
                    "dst_ip": target_ip,
                })

        elif anomaly == "unsolicited":
            # Unsolicited ARP replies sent without request
            current_time += random.uniform(0.05, 0.3)
            src_mac = _random_mac()
            claimed_ip = random.choice(list(ALL_HOSTS.keys()))
            packets.append({
                "timestamp": round(current_time, 6),
                "op": 2,
                "src_mac": src_mac,
                "dst_mac": BROADCAST_MAC,
                "src_ip": claimed_ip,
                "dst_ip": claimed_ip,
            })

    return packets


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Generate synthetic ARP data for ML pipeline validation"
    )
    parser.add_argument(
        "--output",
        default=os.path.join("ml", "data", "sample_arp_data.csv"),
        help="Output CSV file path (default: ml/data/sample_arp_data.csv)",
    )
    parser.add_argument(
        "--num-normal",
        type=int,
        default=1000,
        help="Number of normal traffic packets to generate (default: 1000)",
    )
    parser.add_argument(
        "--num-anomalous",
        type=int,
        default=50,
        help="Number of anomalous traffic events to generate (default: 50)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    random.seed(args.seed)
    base_time = 1700000000.0  # Arbitrary fixed start time for reproducibility

    print("=" * 60)
    print("ARPShield — Synthetic ARP Data Generator")
    print("=" * 60)
    print(f"  Normal packets:    {args.num_normal}")
    print(f"  Anomalous events:  {args.num_anomalous}")
    print(f"  Random seed:       {args.seed}")
    print(f"  Output:            {args.output}")
    print()
    print("  WARNING: This generates SYNTHETIC data for pipeline")
    print("  validation only. NOT real network traffic.")
    print("=" * 60)

    # Generate traffic
    normal_packets = generate_normal_traffic(base_time, args.num_normal)
    anomalous_base = base_time + len(normal_packets) * 3.0
    anomalous_packets = generate_anomalous_traffic(anomalous_base, args.num_anomalous)

    # Interleave: inject anomalous packets at random positions in normal traffic
    all_packets = normal_packets + anomalous_packets
    all_packets.sort(key=lambda p: p["timestamp"])

    # Ensure output directory exists
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)

    # Write CSV
    fieldnames = ["timestamp", "op", "src_mac", "dst_mac", "src_ip", "dst_ip"]
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_packets)

    print(f"\n  Generated {len(all_packets)} total packets")
    print(f"    - Normal:    {len(normal_packets)}")
    print(f"    - Anomalous: {len(anomalous_packets)}")
    print(f"  Saved to: {args.output}")
    print()
    print("  REMINDER: This is synthetic data. Any model trained on")
    print("  this data is for pipeline validation purposes only.")


if __name__ == "__main__":
    main()
