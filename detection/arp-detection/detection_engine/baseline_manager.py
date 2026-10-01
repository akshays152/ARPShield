import json
import os


class BaselineManager:
    def __init__(self, path="config/trusted_baseline.json"):
        self.path = path
        self.gateway_ip = None
        self.gateway_mac = None
        self.trusted = {}
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"Baseline file not found: {self.path}")
        with open(self.path, "r") as f:
            data = json.load(f)
        self.gateway_ip = data.get("gateway_ip")
        self.gateway_mac = data.get("gateway_mac", "").lower()
        self.trusted = {ip: mac.lower() for ip, mac in data.get("trusted_devices", {}).items()}

    def is_trusted(self, ip, mac):
        return self.trusted.get(ip) == mac.lower()

    def get_trusted_mac(self, ip):
        return self.trusted.get(ip)

    def is_gateway_ip(self, ip):
        return ip == self.gateway_ip

    def is_gateway_mac(self, mac):
        return mac.lower() == self.gateway_mac