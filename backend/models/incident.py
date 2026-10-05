from datetime import datetime
from database.database import db


class Incident(db.Model):
    """Correlates multiple security alerts and manages incident triage and response."""
    __tablename__ = "incidents"

    id = db.Column(db.Integer, primary_key=True)

    incident_code = db.Column(db.String(32), nullable=False, unique=True, index=True)
    title = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="HIGH", index=True)
    status = db.Column(db.String(20), nullable=False, default="OPEN", index=True)

    attacker_mac = db.Column(db.String(17), nullable=False, index=True)
    target_ip = db.Column(db.String(45), nullable=True)
    impact_summary = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    alerts = db.relationship("SecurityAlert", backref="incident", lazy="select")
    mitigation_requests = db.relationship(
        "MitigationRequest", backref="incident", lazy="select"
    )

    def to_dict(self, include_relations: bool = False) -> dict:
        data = {
            "id": self.id,
            "incident_code": self.incident_code,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "attacker_mac": self.attacker_mac,
            "target_ip": self.target_ip,
            "impact_summary": self.impact_summary,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }
        if include_relations:
            data["alerts"] = [a.to_dict() for a in self.alerts]
            data["mitigation_requests"] = [m.to_dict() for m in self.mitigation_requests]
        return data
