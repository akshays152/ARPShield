from datetime import datetime
from database.database import db


class RecoveryLog(db.Model):
    """Tracks post-mitigation health checks and recovery telemetry (Person 4 domain).

    Verifies that the network baseline has stabilized after defensive action.
    """
    __tablename__ = "recovery_logs"

    id = db.Column(db.Integer, primary_key=True)

    mitigation_id = db.Column(
        db.Integer,
        db.ForeignKey("mitigation_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    target_mac = db.Column(db.String(17), nullable=False, index=True)
    target_ip = db.Column(db.String(45), nullable=True)

    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    arp_cache_healthy = db.Column(db.Boolean, nullable=False, default=False)
    gateway_reachable = db.Column(db.Boolean, nullable=False, default=False)
    traffic_normalized = db.Column(db.Boolean, nullable=False, default=False)

    # Status: MONITORING, RESTORED, UNSTABLE
    recovery_status = db.Column(db.String(20), nullable=False, default="MONITORING", index=True)
    details = db.Column(db.Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "mitigation_id": self.mitigation_id,
            "target_mac": self.target_mac,
            "target_ip": self.target_ip,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "arp_cache_healthy": self.arp_cache_healthy,
            "gateway_reachable": self.gateway_reachable,
            "traffic_normalized": self.traffic_normalized,
            "recovery_status": self.recovery_status,
            "details": self.details,
        }