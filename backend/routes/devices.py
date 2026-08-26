from flask import Blueprint, request, jsonify

from database.database import db
from backend.models.device import Device


devices_bp = Blueprint(
    "devices",
    __name__,
    url_prefix="/api/devices"
)


@devices_bp.route("/", methods=["POST"])
def add_device():

    data = request.get_json()

    device = Device(
        ip_address=data["ip_address"],
        mac_address=data["mac_address"],
        hostname=data.get("hostname"),
        device_type=data.get("device_type"),
        status=data.get("status", "unknown"),
        trusted=data.get("trusted", False)
    )

    db.session.add(device)
    db.session.commit()

    return jsonify({
        "message": "Device added successfully",
        "device_id": device.id
    }), 201