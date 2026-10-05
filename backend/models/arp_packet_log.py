from datetime import datetime
from database.database import db


class ArpPacketLog(db.Model):
    """Stores sampled and suspicious ARP packet telemetry.

    Designed for capstone-scale SQLite storage:
    - Normal packets are sampled/windowed.
    - Suspicious packets are logged directly.
    - Retained entries are capped at a maximum count (e.g. 5,000) via RetentionService.
    """
    __tablename__ = "arp_packet_logs"

    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    sender_ip = db.Column(db.String(45), nullable=False, index=True)
    sender_mac = db.Column(db.String(17), nullable=False, index=True)
    target_ip = db.Column(db.String(45), nullable=False)
    target_mac = db.Column(db.String(17), nullable=False)

    operation = db.Column(db.String(10), nullable=False)  # "request" or "reply"
    is_gratuitous = db.Column(db.Boolean, nullable=False, default=False)
    packet_size = db.Column(db.Integer, nullable=False, default=42)

    # "sampled" for routine background packets, "suspicious" for flagged packets
    log_type = db.Column(db.String(20), nullable=False, default="sampled", index=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "sender_ip": self.sender_ip,
            "sender_mac": self.sender_mac,
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "operation": self.operation,
            "is_gratuitous": self.is_gratuitous,
            "packet_size": self.packet_size,
            "log_type": self.log_type,
        }