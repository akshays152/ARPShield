import time
from detection_engine.detector import ARPSpoofDetector


def fake_packet(**overrides):
    base = {
        "timestamp": time.time(),
        "src_mac": "11:22:33:44:55:66",
        "src_ip": "192.168.1.10",
        "dst_mac": "ff:ff:ff:ff:ff:ff",
        "dst_ip": "192.168.1.1",
        "op": "reply",
    }
    base.update(overrides)
    return base


if __name__ == "__main__":
    detector = ARPSpoofDetector()

    # Simulated stream
    packets = [
        # normal
        fake_packet(),
        # gateway spoof
        fake_packet(src_mac="de:ad:be:ef:00:01", src_ip="192.168.1.1"),
        # conflict
        fake_packet(src_mac="99:99:99:99:99:99", src_ip="192.168.1.10"),
        # gratuitous ARP
        fake_packet(src_ip="192.168.1.20", dst_ip="192.168.1.20",
                    src_mac="77:88:99:aa:bb:cc"),
    ]

    for pkt in packets:
        alerts = detector.process(pkt)
        for a in alerts:
            print(f"[{a['severity']}] {a['rule']} -> {a['reason']}")