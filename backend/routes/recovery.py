from datetime import datetime

from flask import Blueprint, jsonify, request

from database.database import db
from backend.models.recovery_log import RecoveryLog
from backend.models.mitigation_request import MitigationRequest


recovery_bp = Blueprint(
    "recovery",
    __name__,
    url_prefix="/api/recovery"
)


@recovery_bp.route("/", methods=["GET"])
def get_recovery_logs():

    logs = (
        RecoveryLog.query
        .order_by(RecoveryLog.timestamp.desc())
        .limit(100)
        .all()
    )

    return jsonify({
        "status": "ok",
        "count": len(logs),
        "logs": [
            log.to_dict()
            for log in logs
        ]
    })


@recovery_bp.route("/latest", methods=["GET"])
def get_latest_recovery():

    log = (
        RecoveryLog.query
        .order_by(RecoveryLog.timestamp.desc())
        .first()
    )

    if not log:
        return jsonify({
            "status": "ok",
            "log": None
        })

    return jsonify({
        "status": "ok",
        "log": log.to_dict()
    })


@recovery_bp.route("/", methods=["POST"])
def create_recovery_log():

    data = request.get_json() or {}

    mitigation_id = data.get("mitigation_id")

    if not mitigation_id:
        return jsonify({
            "status": "error",
            "message": "mitigation_id is required"
        }), 400

    mitigation = db.session.get(
        MitigationRequest,
        mitigation_id
    )

    if not mitigation:
        return jsonify({
            "status": "error",
            "message": "Mitigation request not found"
        }), 404

    if mitigation.status != "EXECUTED":
        return jsonify({
            "status": "error",
            "message": (
                "Recovery monitoring can only begin "
                "after mitigation is EXECUTED."
            )
        }), 400

    # Prevent duplicate active recovery records
    existing = (
        RecoveryLog.query
        .filter_by(
            mitigation_id=mitigation.id,
            recovery_status="MONITORING"
        )
        .first()
    )

    if existing:
        return jsonify({
            "status": "ok",
            "message": "Recovery monitoring already exists",
            "log": existing.to_dict()
        })

    recovery_log = RecoveryLog(
        mitigation_id=mitigation.id,
        target_mac=mitigation.target_mac,
        target_ip=mitigation.target_ip,
        recovery_status="MONITORING",
        details="Post-mitigation recovery monitoring started."
    )

    try:
        db.session.add(recovery_log)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        return jsonify({
            "status": "error",
            "message": "Failed to create recovery log",
            "detail": str(error)
        }), 500

    return jsonify({
        "status": "ok",
        "message": "Recovery monitoring started",
        "log": recovery_log.to_dict()
    }), 201


@recovery_bp.route(
    "/<int:recovery_id>/check",
    methods=["POST"]
)
def update_recovery_check(recovery_id):

    recovery_log = db.session.get(
        RecoveryLog,
        recovery_id
    )

    if not recovery_log:
        return jsonify({
            "status": "error",
            "message": "Recovery log not found"
        }), 404

    if recovery_log.recovery_status == "RESTORED":
        return jsonify({
            "status": "error",
            "message": "Recovery has already been marked RESTORED"
        }), 400

    data = request.get_json() or {}

    recovery_log.arp_cache_healthy = bool(
        data.get("arp_cache_healthy", False)
    )

    recovery_log.gateway_reachable = bool(
        data.get("gateway_reachable", False)
    )

    recovery_log.traffic_normalized = bool(
        data.get("traffic_normalized", False)
    )

    all_healthy = (
        recovery_log.arp_cache_healthy
        and recovery_log.gateway_reachable
        and recovery_log.traffic_normalized
    )

    if all_healthy:
        recovery_log.recovery_status = "RESTORED"
        recovery_log.details = (
            "All post-mitigation health checks passed. "
            "Network conditions have stabilized."
        )

        # Mark the associated incident as resolved.
        mitigation = db.session.get(
            MitigationRequest,
            recovery_log.mitigation_id
        )

        if mitigation and mitigation.incident:
            mitigation.incident.status = "RESOLVED"
            mitigation.incident.resolved_at = datetime.utcnow()

    else:
        any_unhealthy = (
            not recovery_log.arp_cache_healthy
            or not recovery_log.gateway_reachable
            or not recovery_log.traffic_normalized
        )

        if any_unhealthy:
            recovery_log.recovery_status = "UNSTABLE"
            recovery_log.details = (
                "One or more post-mitigation health checks "
                "have not passed."
            )

    recovery_log.timestamp = datetime.utcnow()

    try:
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        return jsonify({
            "status": "error",
            "message": "Failed to update recovery status",
            "detail": str(error)
        }), 500

    return jsonify({
        "status": "ok",
        "message": "Recovery health check updated",
        "log": recovery_log.to_dict()
    })