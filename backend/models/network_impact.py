from datetime import datetime
from database.database import db


class NetworkImpactMetric(db.Model):
    """Stores quantitative evaluation and network health metrics (Person 3 domain).

    Tracks packet rates, flood indicators, and host impact over time.
    """
    __tablename__ = "network_impact_metrics"

    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    arp_rate_per_sec = db.Column(db.Float, nullable=False, default=0.0)
    request_reply_ratio = db.Column(db.Float, nullable=False, default=0.0)
    unique_mac_count = db.Column(db.Integer, nullable=False, default=0)
    flood_detected = db.Column(db.Boolean, nullable=False, default=False, index=True)
    affected_hosts_count = db.Column(db.Integer, nullable=False, default=0)
    bandwidth_kbps = db.Column(db.Float, nullable=True)
    details = db.Column(db.Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "arp_rate_per_sec": self.arp_rate_per_sec,
            "request_reply_ratio": self.request_reply_ratio,
            "unique_mac_count": self.unique_mac_count,
            "flood_detected": self.flood_detected,
            "affected_hosts_count": self.affected_hosts_count,
            "bandwidth_kbps": self.bandwidth_kbps,
            "details": self.details,
        }