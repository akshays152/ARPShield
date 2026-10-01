from collections import defaultdict
import time


class ARPTable:
    def __init__(self, mac_change_window=60):
        # ip -> list of (mac, timestamp)
        self.ip_to_macs = defaultdict(list)
        # mac -> list of (ip, timestamp)
        self.mac_to_ips = defaultdict(list)
        self.mac_change_window = mac_change_window

    def update(self, ip, mac, timestamp=None):
        ts = timestamp or time.time()
        mac = mac.lower()
        self.ip_to_macs[ip].append((mac, ts))
        self.mac_to_ips[mac].append((ip, ts))

    def get_macs_for_ip(self, ip):
        return [m for m, _ in self.ip_to_macs.get(ip, [])]

    def get_ips_for_mac(self, mac):
        return [i for i, _ in self.mac_to_ips.get(mac.lower(), [])]

    def has_conflict(self, ip):
        """Same IP claimed by more than one MAC."""
        macs = set(self.get_macs_for_ip(ip))
        return len(macs) > 1

    def has_duplicate_claim(self, mac):
        """Same MAC claiming more than one IP."""
        ips = set(self.get_ips_for_mac(mac))
        return len(ips) > 1

    def mac_changed(self, ip, window=None):
        """Check if a device changed MAC recently."""
        window = window or self.mac_change_window
        now = time.time()
        recent = [m for m, ts in self.ip_to_macs.get(ip, []) if now - ts <= window]
        return len(set(recent)) > 1