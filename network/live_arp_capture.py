import csv
from scapy.all import sniff
from scapy.layers.l2 import ARP

OUTPUT_FILE = "live_arp_data.csv"


def save_arp_packet(pkt):
    if pkt.haslayer(ARP):
        with open(OUTPUT_FILE, "a", newline="") as file:
            writer = csv.writer(file)

            writer.writerow([
                float(pkt.time),
                pkt[ARP].hwsrc.lower(),
                pkt[ARP].psrc,
                pkt[ARP].hwdst.lower(),
                pkt[ARP].pdst,
                pkt[ARP].op
            ])

        print("Captured:", pkt.summary())


# Create CSV header
with open(OUTPUT_FILE, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow([
        "timestamp",
        "source_mac",
        "source_ip",
        "destination_mac",
        "destination_ip",
        "arp_opcode"
    ])

print("Starting live ARP capture...")
print("Saving data to:", OUTPUT_FILE)
print("Press Ctrl+C to stop.")

sniff(
    filter="arp",
    prn=save_arp_packet,
    store=False
)