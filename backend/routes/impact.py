from flask import Blueprint, jsonify, request
from database.database import db
from backend.models.network_impact import NetworkImpactMetric


impact_bp = Blueprint(
    "impact",
    __name__,
    url_prefix="/api/impact"
)


@impact_bp.route("/", methods=["GET"])
def get_impact_history():

    metrics = (
        NetworkImpactMetric.query
        .order_by(NetworkImpactMetric.timestamp.desc())
        .limit(100)
        .all()
    )

    return jsonify({
        "status": "ok",
        "count": len(metrics),
        "metrics": [
            metric.to_dict()
            for metric in metrics
        ]
    })


@impact_bp.route("/latest", methods=["GET"])
def get_latest_impact():

    metric = (
        NetworkImpactMetric.query
        .order_by(NetworkImpactMetric.timestamp.desc())
        .first()
    )

    if not metric:
        return jsonify({
            "status": "ok",
            "metric": None
        })

    return jsonify({
        "status": "ok",
        "metric": metric.to_dict()
    })

@impact_bp.route("/", methods=["POST"])
def create_impact_metric():

    data = request.get_json() or {}

    required_fields = [
        "arp_rate_per_sec",
        "request_reply_ratio",
        "unique_mac_count",
        "flood_detected",
        "affected_hosts_count"
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in data
    ]

    if missing_fields:
        return jsonify({
            "status": "error",
            "message": "Missing required fields",
            "missing_fields": missing_fields
        }), 400

    metric = NetworkImpactMetric(
        arp_rate_per_sec=float(data["arp_rate_per_sec"]),
        request_reply_ratio=float(data["request_reply_ratio"]),
        unique_mac_count=int(data["unique_mac_count"]),
        flood_detected=bool(data["flood_detected"]),
        affected_hosts_count=int(data["affected_hosts_count"]),
        bandwidth_kbps=(
            float(data["bandwidth_kbps"])
            if data.get("bandwidth_kbps") is not None
            else None
        ),
        details=data.get("details")
    )

    try:
        db.session.add(metric)
        db.session.commit()

    except Exception as error:
        db.session.rollback()

        return jsonify({
            "status": "error",
            "message": "Failed to store network impact metric",
            "detail": str(error)
        }), 500

    return jsonify({
        "status": "ok",
        "message": "Network impact metric created",
        "metric": metric.to_dict()
    }), 201