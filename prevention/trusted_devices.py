"""Persistent trusted-device management for ARPShield."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import List


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TrustedDevice:
    mac: str
    ip: str | None = None
    label: str = ""
    added_at: str = ""


class TrustedDeviceStore:
    def __init__(self, path: str = "prevention/trusted_devices.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._devices = self._load()

    def _load(self) -> List[TrustedDevice]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text())
            return [TrustedDevice(**item) for item in raw]
        except (json.JSONDecodeError, TypeError, KeyError):
            return []

    def _save(self) -> None:
        self.path.write_text(
            json.dumps([asdict(d) for d in self._devices], indent=2)
        )

    @staticmethod
    def normalize_mac(mac: str) -> str:
        return mac.strip().lower().replace("-", ":")

    def add(self, mac: str, ip: str | None = None, label: str = "") -> TrustedDevice:
        mac = self.normalize_mac(mac)
        existing = self.get(mac)
        if existing:
            if ip is not None:
                existing.ip = ip
            if label:
                existing.label = label
            self._save()
            return existing

        device = TrustedDevice(
            mac=mac,
            ip=ip,
            label=label,
            added_at=_now(),
        )
        self._devices.append(device)
        self._save()
        return device

    def remove(self, mac: str) -> bool:
        mac = self.normalize_mac(mac)
        before = len(self._devices)
        self._devices = [d for d in self._devices if d.mac != mac]
        changed = len(self._devices) != before
        if changed:
            self._save()
        return changed

    def get(self, mac: str) -> TrustedDevice | None:
        mac = self.normalize_mac(mac)
        return next((d for d in self._devices if d.mac == mac), None)

    def is_trusted(self, mac: str, ip: str | None = None) -> bool:
        device = self.get(mac)
        if not device:
            return False
        return device.ip is None or ip is None or device.ip == ip

    def list_devices(self) -> List[TrustedDevice]:
        return list(self._devices)
