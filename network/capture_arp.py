from scapy.all import sniff, ARP
import csv
from datetime import datetime

PACKET_COUNT = 5000
OUTPUT_FILE = "arp_dataset.csv"

data = []


def capture_packet(packet):
    if packet.haslayer(ARP):

        arp = packet[ARP]

        operation = "request" if arp.op == 1 else "reply"

        data.append([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            arp.psrc,
            arp.hwsrc,
            arp.pdst,
            arp.hwdst,
            operation
        ])

        # Show progress without flooding the terminal
        if len(data) % 100 == 0:
            print(f"Captured {len(data)} ARP packets...")


print(f"Starting ARP capture. Target: {PACKET_COUNT} packets")

sniff(
    filter="arp",
    prn=capture_packet,
    store=False,
    count=PACKET_COUNT
)

with open(OUTPUT_FILE, "w", newline="") as file:

    writer = csv.writer(file)

    writer.writerow([
        "timestamp",
        "sender_ip",
        "sender_mac",
        "target_ip",
        "target_mac",
        "operation"
    ])

    writer.writerows(data)

print(f"\nCapture complete!")
print(f"Total ARP packets captured: {len(data)}")
print(f"Dataset saved as: {OUTPUT_FILE}")