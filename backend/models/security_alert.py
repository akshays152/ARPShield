import json
from datetime import datetime
from database.database import db


class SecurityAlert(db.Model):
    """Stores rule-based detection results produced by Person 2's detection engine.

    Strictly rule-based: no ML anomaly scores or confidence probabilities.
    Emphasizes rule_name, severity, reason, evidence, and suspicious/affected endpoints.
    Note: suspicious_ip is NULLABLE because an attacker MAC may spoof packets
    without disclosing their own IP.
    """
    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)

    alert_id = db.Column(db.String(64), nullable=False, unique=True, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    rule_name = db.Column(db.String(100), nullable=False, index=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    reason = db.Column(db.Text, nullable=False)

    # Offender / Suspicious device identifiers
    suspicious_mac = db.Column(db.String(17), nullable=False, index=True)
    suspicious_ip = db.Column(db.String(45), nullable=True, index=True)  # NULLABLE

    # Target / Victim device identifiers
    victim_mac = db.Column(db.String(17), nullable=True)
    victim_ip = db.Column(db.String(45), nullable=True)

    # Detailed rule findings and packet context stored as JSON text
    evidence_data = db.Column(db.Text, nullable=True)

    # Foreign key to Incident
    incident_id = db.Column(
        db.Integer, db.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )

    def set_evidence(self, data: dict | list) -> None:
        """Helper to serialize evidence dictionary as JSON string."""
        self.evidence_data = json.dumps(data) if data is not None else None

    def get_evidence(self) -> dict | list | None:
        """Helper to deserialize evidence JSON string."""
        if not self.evidence_data:
            return None
        try:
            return json.loads(self.evidence_data)
        except (json.JSONDecodeError, TypeError):
            return self.evidence_data

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "rule_name": self.rule_name,
            "event_type": self.event_type,
            "severity": self.severity,
            "reason": self.reason,
            "suspicious_mac": self.suspicious_mac,
            "suspicious_ip": self.suspicious_ip,
            "victim_mac": self.victim_mac,
            "victim_ip": self.victim_ip,
            "evidence": self.get_evidence(),
            "incident_id": self.incident_id,
        }