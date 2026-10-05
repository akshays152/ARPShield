from datetime import datetime
import uuid

from flask import Blueprint, jsonify, request

from database.database import db
from backend.models.mitigation_request import MitigationRequest
from backend.models.incident import Incident


mitigation_bp = Blueprint(
    "mitigation",
    __name__,
    url_prefix="/api/mitigation"
)


@mitigation_bp.route("/", methods=["GET"])
def get_mitigation_requests():

    requests = (
        MitigationRequest.query
        .order_by(MitigationRequest.created_at.desc())
        .all()
    )

    return jsonify({
        "status": "ok",
        "count": len(requests),
        "requests": [
            item.to_dict()
            for item in requests
        ]
    })


@mitigation_bp.route("/", methods=["POST"])
def create_mitigation_request():

    data = request.get_json() or {}

    required_fields = [
        "incident_id",
        "action_type",
        "target_mac",
        "target_ip",
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

    incident = db.session.get(
        Incident,
        data["incident_id"]
    )

    if not incident:
        return jsonify({
            "status": "error",
            "message": "Incident not found"
        }), 404

    request_code = f"MIT-{uuid.uuid4().hex[:8].upper()}"

    mitigation = MitigationRequest(
        request_code=request_code,
        incident_id=incident.id,
        action_type=data["action_type"],
        target_mac=data["target_mac"],
        target_ip=data["target_ip"],
        reason=data["reason"],
        status="PENDING"
    )

    try:
        db.session.add(mitigation)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        return jsonify({
            "status": "error",
            "message": "Failed to create mitigation request",
            "detail": str(error)
        }), 500

    return jsonify({
        "status": "ok",
        "message": "Mitigation request created",
        "request": mitigation.to_dict()
    }), 201


@mitigation_bp.route("/<int:request_id>", methods=["GET"])
def get_mitigation_request(request_id):

    item = db.session.get(
        MitigationRequest,
        request_id
    )

    if not item:
        return jsonify({
            "status": "error",
            "message": "Mitigation request not found"
        }), 404

    return jsonify({
        "status": "ok",
        "request": item.to_dict()
    })


@mitigation_bp.route(
    "/<int:request_id>/approve",
    methods=["POST"]
)
def approve_mitigation(request_id):

    item = db.session.get(
        MitigationRequest,
        request_id
    )

    if not item:
        return jsonify({
            "status": "error",
            "message": "Mitigation request not found"
        }), 404

    if item.status != "PENDING":
        return jsonify({
            "status": "error",
            "message": (
                f"Request cannot be approved "
                f"from status {item.status}"
            )
        }), 400

    data = request.get_json() or {}

    item.status = "APPROVED"
    item.approved_by = data.get(
        "approved_by",
        "dashboard-admin"
    )

    db.session.commit()

    return jsonify({
        "status": "ok",
        "message": "Mitigation request approved",
        "request": item.to_dict()
    })


@mitigation_bp.route(
    "/<int:request_id>/reject",
    methods=["POST"]
)
def reject_mitigation(request_id):

    item = db.session.get(
        MitigationRequest,
        request_id
    )

    if not item:
        return jsonify({
            "status": "error",
            "message": "Mitigation request not found"
        }), 404

    if item.status != "PENDING":
        return jsonify({
            "status": "error",
            "message": (
                f"Request cannot be rejected "
                f"from status {item.status}"
            )
        }), 400

    item.status = "REJECTED"

    db.session.commit()

    return jsonify({
        "status": "ok",
        "message": "Mitigation request rejected",
        "request": item.to_dict()
    })


@mitigation_bp.route(
    "/<int:request_id>/execute",
    methods=["POST"]
)
def execute_mitigation(request_id):

    item = db.session.get(
        MitigationRequest,
        request_id
    )

    if not item:
        return jsonify({
            "status": "error",
            "message": "Mitigation request not found"
        }), 404

    if item.status != "APPROVED":
        return jsonify({
            "status": "error",
            "message": (
                "Mitigation must be APPROVED "
                "before execution."
            )
        }), 400

    data = request.get_json() or {}

    item.status = "EXECUTED"
    item.execution_result = data.get(
        "execution_result",
        "Execution delegated to mitigation engine."
    )
    item.executed_at = datetime.utcnow()

    db.session.commit()

    return jsonify({
        "status": "ok",
        "message": "Mitigation marked as executed",
        "request": item.to_dict()
    })