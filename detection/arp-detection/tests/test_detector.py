import time

import pytest

from detection_engine.detector import ARPSpoofDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make(
    mac: str,
    ip: str,
    op: str = "reply",
    dst_ip: str = "192.168.1.1",
    dst_mac: str = "aa:bb:cc:dd:ee:01",
    timestamp: float | None = None,
) -> dict:
    """
    Build a synthetic ARP packet dict for testing.

    Defaults describe a *normal* unicast ARP reply:
      - src_mac / src_ip : the sender
      - dst_mac         : unicast (NOT broadcast)
      - dst_ip          : the target
      - op              : "reply"
    """
    return {
        "timestamp": timestamp if timestamp is not None else time.time(),
        "src_mac": mac.lower(),
        "src_ip": ip,
        "dst_mac": dst_mac.lower(),
        "dst_ip": dst_ip,
        "op": op,
    }


def rules_fired(alerts: list[dict]) -> set[str]:
    """Return the set of rule names present in an alert list."""
    return {a["rule"] for a in alerts}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_normal_traffic_no_alert():
    """A plain unicast ARP reply from a trusted device should not alert."""
    d = ARPSpoofDetector()
    alerts = d.process(make("11:22:33:44:55:66", "192.168.1.10"))
    assert alerts == [], f"Expected no alerts, got: {alerts}"


def test_gateway_spoof():
    """A non-gateway MAC claiming the gateway IP must trigger Critical."""
    d = ARPSpoofDetector()
    alerts = d.process(make("de:ad:be:ef:00:01", "192.168.1.1"))
    fired = rules_fired(alerts)
    assert "gateway_impersonation" in fired, f"Got: {fired}"
    assert any(a["severity"] == "Critical" for a in alerts)


def test_ip_mac_conflict():
    """Same IP claimed by two different MACs should trigger conflict alert."""
    d = ARPSpoofDetector()
    d.process(make("11:22:33:44:55:66", "192.168.1.10"))
    alerts = d.process(make("99:99:99:99:99:99", "192.168.1.10"))
    fired = rules_fired(alerts)
    assert "ip_mac_conflict" in fired, f"Got: {fired}"


def test_baseline_violation():
    """A MAC that mismatches the trusted baseline should be flagged."""
    d = ARPSpoofDetector()
    # 192.168.1.10 is trusted with MAC 11:22:33:44:55:66 in config
    alerts = d.process(make("ab:cd:ef:00:00:01", "192.168.1.10"))
    fired = rules_fired(alerts)
    assert "baseline_violation" in fired, f"Got: {fired}"


def test_mac_change_detection():
    """A MAC change for a known IP within the window should be flagged."""
    d = ARPSpoofDetector()
    d.process(make("11:22:33:44:55:66", "192.168.1.20"))
    alerts = d.process(make("77:88:99:aa:bb:cc", "192.168.1.20"))
    fired = rules_fired(alerts)
    assert "mac_change" in fired, f"Got: {fired}"


def test_gratuitous_arp():
    """An unsolicited ARP reply (src IP == dst IP) should be flagged Low."""
    d = ARPSpoofDetector()
    alerts = d.process(make("77:88:99:aa:bb:cc", "192.168.1.20",
                            dst_ip="192.168.1.20"))
    fired = rules_fired(alerts)
    assert "gratuitous_arp" in fired, f"Got: {fired}"


def test_broadcast_reply_is_flagged():
    """An ARP reply sent to broadcast MAC should be flagged Low."""
    d = ARPSpoofDetector()
    alerts = d.process(make("11:22:33:44:55:66", "192.168.1.10",
                            dst_mac="ff:ff:ff:ff:ff:ff"))
    fired = rules_fired(alerts)
    assert "suspicious_arp_reply" in fired, f"Got: {fired}"


def test_rate_threshold():
    """A burst of 60 ARP packets from one MAC should trigger a rate rule."""
    d = ARPSpoofDetector()
    mac = "aa:aa:aa:aa:aa:aa"
    alerts = []
    now = time.time()
    for i in range(60):
        # same-MAC packets within the 1-second sliding window
        alerts = d.process(make(mac, "192.168.1.99", timestamp=now + i * 0.001))
    fired = rules_fired(alerts)
    assert any(r.startswith("rate_threshold") for r in fired), f"Got: {fired}"


def test_rate_threshold_critical():
    """A flood of 600 ARP packets/sec should escalate to Critical."""
    d = ARPSpoofDetector()
    mac = "bb:bb:bb:bb:bb:bb"
    alerts = []
    now = time.time()
    for i in range(600):
        alerts = d.process(make(mac, "192.168.1.98", timestamp=now + i * 0.001))
    assert any(a["severity"] == "Critical" for a in alerts), \
        f"Expected Critical, got: {alerts}"

def test_baseline_loaded():
    """BaselineManager should load the gateway and trusted devices."""
    d = ARPSpoofDetector()
    assert d.ctx.baseline.gateway_ip == "192.168.1.1"
    assert d.ctx.baseline.gateway_mac == "aa:bb:cc:dd:ee:01"
    assert "192.168.1.10" in d.ctx.baseline.trusted
