from datetime import datetime
from database.database import db


class Device(db.Model):
    """Represents a discovered physical device on the local network.

    Note: ip_address is NOT unique because during ARP spoofing attacks, multiple
    devices / MACs claim the same IP address.
    """
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)

    # Identifiers (indexed for fast lookups)
    mac_address = db.Column(db.String(17), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)

    hostname = db.Column(db.String(255), nullable=True)
    vendor = db.Column(db.String(100), nullable=True)
    device_type = db.Column(db.String(100), nullable=True)

    # Security state: normal, suspicious, isolated
    status = db.Column(db.String(20), nullable=False, default="normal", index=True)

    # Whitelist / trust flag
    trusted = db.Column(db.Boolean, nullable=False, default=False, index=True)

    first_seen = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    last_seen = db.Column(
        db.DateTime, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "status": self.status,
            "trusted": self.trusted,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }