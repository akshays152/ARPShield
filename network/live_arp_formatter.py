from scapy.layers.l2 import ARP


def process_arp_packet(pkt):
    if not pkt.haslayer(ARP):
        return None

    return {
        "timestamp": float(pkt.time),
        "src_mac": pkt[ARP].hwsrc.lower(),
        "src_ip": pkt[ARP].psrc,
        "dst_mac": pkt[ARP].hwdst.lower(),
        "dst_ip": pkt[ARP].pdst,
        "op": pkt[ARP].op
    }