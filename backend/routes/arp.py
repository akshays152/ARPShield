from datetime import datetime

from flask import Blueprint, request, jsonify

from database.database import db
from backend.models.arp_packet_log import ArpPacketLog
from backend.services.retention_service import RetentionService


arp_bp = Blueprint(
    "arp",
    __name__,
    url_prefix="/api/arp"
)

retention_service = RetentionService()


@arp_bp.route("/packets", methods=["POST"])
def ingest_packets():
    """
    Receive a batch of ARP packets from the network capture module.

    Expected payload:
    {
        "packets": [
            {
                "timestamp": "...",
                "sender_ip": "...",
                "sender_mac": "...",
                "target_ip": "...",
                "target_mac": "...",
                "operation": "request"
            }
        ]
    }
    """

    data = request.get_json(silent=True) or {}
    packets = data.get("packets")

    if not isinstance(packets, list):
        return jsonify({
            "status": "error",
            "message": "'packets' must be a list"
        }), 400

    if not packets:
        return jsonify({
            "status": "ok",
            "received": 0,
            "logged": 0
        }), 200

    required_fields = [
        "sender_ip",
        "sender_mac",
        "target_ip",
        "target_mac"
    ]

    for index, packet in enumerate(packets):
        missing = [
            field
            for field in required_fields
            if not packet.get(field)
        ]

        if missing:
            return jsonify({
                "status": "error",
                "message": f"Packet {index} is missing required fields",
                "missing": missing
            }), 400

    try:
        for packet in packets:
            if packet.get("timestamp"):
                packet["timestamp"] = datetime.fromisoformat(
                    packet["timestamp"].replace("Z", "+00:00")
                ).replace(tzinfo=None)

        logged_count = retention_service.record_batch(packets)

        return jsonify({
            "status": "ok",
            "received": len(packets),
            "logged": logged_count
        }), 201

    except Exception as exc:
        db.session.rollback()

        return jsonify({
            "status": "error",
            "message": "Failed to store ARP packet batch",
            "detail": str(exc)
        }), 500


@arp_bp.route("/packets", methods=["GET"])
def get_packets():
    """Return recent stored ARP packet logs."""

    limit = request.args.get("limit", default=100, type=int)
    limit = max(1, min(limit, 500))

    packets = (
        ArpPacketLog.query
        .order_by(ArpPacketLog.timestamp.desc())
        .limit(limit)
        .all()
    )

    return jsonify({
        "status": "ok",
        "count": len(packets),
        "packets": [
            packet.to_dict()
            for packet in packets
        ]
    })


@arp_bp.route("/stats", methods=["GET"])
def get_arp_stats():
    """Return ARP packet storage statistics."""

    return jsonify({
        "status": "ok",
        "stats": retention_service.get_storage_stats()
    })