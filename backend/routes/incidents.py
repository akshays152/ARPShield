from flask import Blueprint, jsonify, request

from database.database import db
from backend.models.incident import Incident


incidents_bp = Blueprint(
    "incidents",
    __name__,
    url_prefix="/api/incidents"
)


@incidents_bp.route("/", methods=["GET"])
def get_incidents():

    incidents = (
        Incident.query
        .order_by(Incident.created_at.desc())
        .all()
    )

    return jsonify({
        "status": "ok",
        "count": len(incidents),
        "incidents": [
            incident.to_dict()
            for incident in incidents
        ]
    })


@incidents_bp.route("/<int:incident_id>", methods=["GET"])
def get_incident(incident_id):

    incident = db.session.get(
        Incident,
        incident_id
    )

    if not incident:
        return jsonify({
            "status": "error",
            "message": "Incident not found"
        }), 404

    return jsonify({
        "status": "ok",
        "incident": incident.to_dict(
            include_relations=True
        )
    })


@incidents_bp.route("/<int:incident_id>", methods=["PATCH"])
def update_incident(incident_id):

    incident = db.session.get(
        Incident,
        incident_id
    )

    if not incident:
        return jsonify({
            "status": "error",
            "message": "Incident not found"
        }), 404

    data = request.get_json() or {}

    allowed_fields = [
        "title",
        "severity",
        "status",
        "impact_summary",
        "target_ip"
    ]

    for field in allowed_fields:

        if field in data:
            setattr(
                incident,
                field,
                data[field]
            )

    if data.get("status") == "RESOLVED":
        from datetime import datetime
        incident.resolved_at = datetime.utcnow()

    db.session.commit()

    return jsonify({
        "status": "ok",
        "message": "Incident updated successfully",
        "incident": incident.to_dict()
    })