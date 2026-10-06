import csv
import os
from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP

RAW_DIR = r"D:\ARPShield_Data\ddos_raw"
OUTPUT_DIR = r"D:\ARPShield_Data\ddos_processed"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "ddos_reference_dataset.csv")

os.makedirs(OUTPUT_DIR, exist_ok=True)

pcap_files = {
    "CIC-DDoS-2019-Benign.pcap": ("Normal", "Benign"),
    "CIC-DDoS-2019-DNS.pcap": ("Attack", "DNS DDoS"),
    "CIC-DDoS-2019-SynFlood.pcap": ("Attack", "SYN Flood"),
    "CIC-DDoS-2019-UDPLag.pcap": ("Attack", "UDP-Lag"),
    "CIC-DDoS-2019-WebDDoS.pcap": ("Attack", "WebDDoS")
}

columns = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_mac",
    "destination_mac",
    "protocol",
    "source_port",
    "destination_port",
    "packet_length",
    "label",
    "attack_type"
]

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:

    writer = csv.writer(file)
    writer.writerow(columns)

    for filename, (label, attack_type) in pcap_files.items():

        filepath = os.path.join(RAW_DIR, filename)

        print(f"Processing: {filename}")

        packet_count = 0

        with PcapReader(filepath) as packets:

            for pkt in packets:

                if not pkt.haslayer(IP):
                    continue

                ip = pkt[IP]

                source_port = ""
                destination_port = ""

                if pkt.haslayer(TCP):
                    protocol = "TCP"
                    source_port = pkt[TCP].sport
                    destination_port = pkt[TCP].dport

                elif pkt.haslayer(UDP):
                    protocol = "UDP"
                    source_port = pkt[UDP].sport
                    destination_port = pkt[UDP].dport

                else:
                    protocol = ip.proto

                source_mac = ""
                destination_mac = ""

                if hasattr(pkt, "src"):
                    source_mac = pkt.src.lower()

                if hasattr(pkt, "dst"):
                    destination_mac = pkt.dst.lower()

                writer.writerow([
                    float(pkt.time),
                    ip.src,
                    ip.dst,
                    source_mac,
                    destination_mac,
                    protocol,
                    source_port,
                    destination_port,
                    len(pkt),
                    label,
                    attack_type
                ])

                packet_count += 1

        print(f"  Packets processed: {packet_count}")

print("\nDDoS preprocessing complete.")
print("Output:", OUTPUT_FILE)