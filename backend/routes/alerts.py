from datetime import datetime
import json
import uuid

from flask import Blueprint, jsonify, request

from database.database import db
from backend.models.security_alert import SecurityAlert
from backend.models.incident import Incident


alerts_bp = Blueprint(
    "alerts",
    __name__,
    url_prefix="/api/alerts"
)


# ============================================================
# GET ALL ALERTS
# ============================================================

@alerts_bp.route("/", methods=["GET"])
def get_alerts():

    alerts = (
        SecurityAlert.query
        .order_by(SecurityAlert.timestamp.desc())
        .all()
    )

    return jsonify({
        "status": "ok",
        "count": len(alerts),
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ]
    })


# ============================================================
# GET ALERT SUMMARY
# ============================================================

@alerts_bp.route("/summary", methods=["GET"])
def get_alert_summary():

    alerts = SecurityAlert.query.all()

    summary = {
        "total": len(alerts),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for alert in alerts:

        severity = (
            alert.severity or "low"
        ).lower()

        if severity in summary:
            summary[severity] += 1

    return jsonify({
        "status": "ok",
        "summary": summary
    })


# ============================================================
# CREATE SECURITY ALERT
# ============================================================

@alerts_bp.route("/", methods=["POST"])
def create_alert():

    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "JSON request body is required"
        }), 400

    # --------------------------------------------------------
    # Required detection fields
    # --------------------------------------------------------

    required_fields = [
        "detection_id",
        "event_type",
        "severity",
        "reason"
    ]

    missing_fields = [
        field
        for field in required_fields
        if not data.get(field)
    ]

    if missing_fields:
        return jsonify({
            "status": "error",
            "message": "Missing required fields",
            "missing_fields": missing_fields
        }), 400


    # --------------------------------------------------------
    # Prevent duplicate detection alerts
    # --------------------------------------------------------

    existing_alert = SecurityAlert.query.filter_by(
        alert_id=data["detection_id"]
    ).first()

    if existing_alert:
        return jsonify({
            "status": "ok",
            "message": "Alert already exists",
            "alert_id": existing_alert.alert_id,
            "alert": existing_alert.to_dict()
        }), 200


    # --------------------------------------------------------
    # Detection information
    # --------------------------------------------------------

    affected_device = data.get(
        "affected_device",
        {}
    )

    additional_info = data.get(
        "additional_info",
        {}
    )


    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    timestamp = datetime.utcnow()

    if data.get("timestamp"):

        try:
            timestamp = datetime.fromisoformat(
                data["timestamp"].replace("Z", "+00:00")
            ).replace(tzinfo=None)

        except (ValueError, TypeError):
            pass


    # --------------------------------------------------------
    # Create SecurityAlert
    # --------------------------------------------------------

    alert = SecurityAlert(

        alert_id=data["detection_id"],

        timestamp=timestamp,

        rule_name=data["event_type"],

        event_type=data["event_type"],

        severity=data["severity"],

        reason=data["reason"],

        suspicious_mac=affected_device.get("mac"),

        suspicious_ip=affected_device.get("ip"),

        victim_mac=additional_info.get("victim_mac"),

        victim_ip=additional_info.get("victim_ip"),

        evidence_data=json.dumps({
            "affected_device": affected_device,
            "additional_info": additional_info,
            "source_packet": data.get("source_packet")
        })

    )


    # --------------------------------------------------------
    # Save alert and create/reuse incident
    # --------------------------------------------------------

    try:

        db.session.add(alert)
        db.session.flush()

        incident = None

        # Only HIGH and CRITICAL alerts create incidents.
        # Lower-severity alerts remain alerts without
        # opening a full incident.
        if data["severity"].upper() in ["HIGH", "CRITICAL"]:

            attacker_mac = affected_device.get("mac")
            target_ip = additional_info.get("victim_ip")

            if attacker_mac:

                # Look for an already-active incident involving
                # the same suspicious device.
                active_incidents = (
                    Incident.query
                    .filter(
                        Incident.attacker_mac == attacker_mac,
                        Incident.status.in_(["OPEN", "MITIGATING"])
                    )
                    .order_by(Incident.created_at.desc())
                    .all()
                )

                # Reuse an incident for the same target when possible.
                for existing_incident in active_incidents:

                    if existing_incident.target_ip == target_ip:
                        incident = existing_incident
                        break

                # No active incident exists → create one.
                if incident is None:

                    incident_code = (
                        f"INC-{uuid.uuid4().hex[:8].upper()}"
                    )

                    incident = Incident(

                        incident_code=incident_code,

                        title=(
                            f"{data['event_type']} detected"
                        ),

                        severity=data["severity"].upper(),

                        status="OPEN",

                        attacker_mac=attacker_mac,

                        target_ip=target_ip,

                        impact_summary=data["reason"]

                    )

                    db.session.add(incident)
                    db.session.flush()

                # Link the security alert to the incident.
                alert.incident_id = incident.id

        db.session.commit()

    except Exception as e:

        db.session.rollback()

        return jsonify({
            "status": "error",
            "message": "Failed to store security alert or incident",
            "detail": str(e)
        }), 500


    return jsonify({
        "status": "ok",
        "message": "Security alert created",
        "alert_id": alert.alert_id,
        "incident_id": alert.incident_id,
        "alert": alert.to_dict()
    }), 201