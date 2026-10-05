from datetime import datetime
from database.database import db


class IpMacMapping(db.Model):
    """Tracks active IP-to-MAC baseline bindings, change counts, and detected conflicts.

    Used to compare live ARP traffic against established network baselines.
    """
    __tablename__ = "ip_mac_mappings"

    id = db.Column(db.Integer, primary_key=True)

    ip_address = db.Column(db.String(45), nullable=False, index=True)
    current_mac = db.Column(db.String(17), nullable=False, index=True)
    previous_mac = db.Column(db.String(17), nullable=True)

    is_gateway = db.Column(db.Boolean, nullable=False, default=False, index=True)
    conflict_detected = db.Column(db.Boolean, nullable=False, default=False, index=True)
    change_count = db.Column(db.Integer, nullable=False, default=0)

    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "current_mac": self.current_mac,
            "previous_mac": self.previous_mac,
            "is_gateway": self.is_gateway,
            "conflict_detected": self.conflict_detected,
            "change_count": self.change_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }