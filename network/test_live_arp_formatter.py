from scapy.layers.l2 import ARP
from live_arp_formatter import process_arp_packet

pkt = ARP(
    op=2,
    hwsrc="8C:88:2B:40:07:BE",
    psrc="192.168.0.3",
    hwdst="E4:5F:01:96:47:65",
    pdst="192.168.0.101"
)

result = process_arp_packet(pkt)

print(result)