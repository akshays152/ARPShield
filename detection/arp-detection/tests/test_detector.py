import time
from detection_engine.detector import ARPSpoofDetector


def make(mac, ip, op="reply", dst_ip="192.168.1.1", dst_mac="ff:ff:ff:ff:ff:ff"):
    return {"timestamp": time.time(), "src_mac": mac, "src_ip": ip,
            "dst_mac": dst_mac, "dst_ip": dst_ip, "op": op}


def test_normal_traffic_no_alert():
    d = ARPSpoofDetector()
    assert d.process(make("11:22:33:44:55:66", "192.168.1.10")) == []


def test_gateway_spoof():
    d = ARPSpoofDetector()
    alerts = d.process(make("de:ad:be:ef:00:01", "192.168.1.1"))
    assert any(a["rule"] == "gateway_impersonation" for a in alerts)


def test_ip_mac_conflict():
    d = ARPSpoofDetector()
    d.process(make("11:22:33:44:55:66", "192.168.1.10"))
    alerts = d.process(make("99:99:99:99:99:99", "192.168.1.10"))
    assert any(a["rule"] == "ip_mac_conflict" for a in alerts)


def test_rate_threshold():
    d = ARPSpoofDetector()
    mac = "aa:aa:aa:aa:aa:aa"
    alerts = []
    for _ in range(60):
        alerts = d.process(make(mac, "192.168.1.99"))
    assert any(a["rule"].startswith("rate_threshold") for a in alerts)