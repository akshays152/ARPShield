from scapy.all import sniff, ARP
import csv
from datetime import datetime

PACKET_COUNT = 2000
OUTPUT_FILE ="arp_capture_session_5.csv"

# Consistent schema for network, ML and backend modules
FIELDS = [
    "timestamp",
    "sender_ip",
    "sender_mac",
    "target_ip",
    "target_mac",
    "operation"
]

data = []


def capture_packet(packet):
    if packet.haslayer(ARP):

        arp = packet[ARP]

        # Keep operation values consistent
        if arp.op == 1:
            operation = "request"
        elif arp.op == 2:
            operation = "reply"
        else:
            operation = "unknown"

        # Structured ARP record
        record = {
            "timestamp": datetime.fromtimestamp(
                float(packet.time)
            ).strftime("%Y-%m-%d %H:%M:%S"),

            "sender_ip": arp.psrc,
            "sender_mac": arp.hwsrc,
            "target_ip": arp.pdst,
            "target_mac": arp.hwdst,
            "operation": operation
        }

        data.append(record)

        # Show progress every 100 packets
        if len(data) % 100 == 0:
            print(f"Captured {len(data)} ARP packets...")


print(f"Starting ARP capture. Target: {PACKET_COUNT} packets")

sniff(
    filter="arp",
    prn=capture_packet,
    store=False,
    count=PACKET_COUNT
)


# Save structured output
with open(
    OUTPUT_FILE,
    "w",
    newline=""
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=FIELDS
    )

    writer.writeheader()
    writer.writerows(data)


print("\nCapture complete!")
print(f"Total ARP packets captured: {len(data)}")
print(f"Dataset saved as: {OUTPUT_FILE}")
print("Output schema:", ", ".join(FIELDS))