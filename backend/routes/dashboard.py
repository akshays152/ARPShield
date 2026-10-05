from flask import Blueprint, jsonify
from sqlalchemy import func

from database.database import db
from backend.models.device import Device
from backend.models.arp_packet_log import ArpPacketLog
from backend.models.security_alert import SecurityAlert
from backend.models.incident import Incident
from backend.models.network_impact import NetworkImpactMetric


dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/api/dashboard"
)


@dashboard_bp.route("/overview", methods=["GET"])
def overview():
    """
    Return the data required by the ARPShield dashboard overview page.
    """

    # -----------------------------
    # DEVICE COUNTS
    # -----------------------------

    total_devices = Device.query.count()

    suspicious_devices = Device.query.filter_by(
        status="suspicious"
    ).count()

    isolated_devices = Device.query.filter_by(
        status="isolated"
    ).count()


    # -----------------------------
    # ARP TRAFFIC
    # -----------------------------

    total_arp_packets = ArpPacketLog.query.count()


    # -----------------------------
    # INCIDENTS
    # -----------------------------

    open_incidents = Incident.query.filter(
        Incident.status.in_(["OPEN", "MITIGATING"])
    ).count()


    # -----------------------------
    # ALERTS
    # -----------------------------

    active_alerts = SecurityAlert.query.count()


    recent_alerts = (
        SecurityAlert.query
        .order_by(SecurityAlert.timestamp.desc())
        .limit(5)
        .all()
    )


    alerts = []

    for alert in recent_alerts:
        alerts.append({
            "id": alert.alert_id,
            "rule": alert.rule_name,
            "event_type": alert.event_type,
            "severity": alert.severity,
            "reason": alert.reason,
            "timestamp": (
                alert.timestamp.isoformat()
                if alert.timestamp
                else None
            )
        })


    # -----------------------------
    # LATEST NETWORK IMPACT
    # -----------------------------

    latest_impact = (
        NetworkImpactMetric.query
        .order_by(NetworkImpactMetric.timestamp.desc())
        .first()
    )

    impact = None

    if latest_impact:
        impact = {
            "arp_rate_per_sec": latest_impact.arp_rate_per_sec,
            "request_reply_ratio": latest_impact.request_reply_ratio,
            "unique_mac_count": latest_impact.unique_mac_count,
            "flood_detected": latest_impact.flood_detected,
            "affected_hosts_count": latest_impact.affected_hosts_count,
            "bandwidth_kbps": latest_impact.bandwidth_kbps
        }


    return jsonify({
        "status": "ok",

        "devices": {
            "total": total_devices,
            "suspicious": suspicious_devices,
            "isolated": isolated_devices
        },

        "arp": {
            "total_packets": total_arp_packets
        },

        "security": {
            "active_alerts": active_alerts,
            "open_incidents": open_incidents
        },

        "recent_alerts": alerts,

        "network_impact": impact
    })