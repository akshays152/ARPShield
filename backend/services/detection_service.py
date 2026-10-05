import requests

from detection.src.detection_models import (
    ARPPacket,
    ARPOperation,
)
from detection.src.detection_manager import DetectionManager


class DetectionService:
    """
    Connects the rule-based ARP detection engine
    with the Flask backend.
    """

    def __init__(self, gateway_ips=None):

        if gateway_ips is None:
            gateway_ips = ["172.25.160.47"]

        self.manager = DetectionManager(
            gateway_ips=gateway_ips
        )

        self.backend_url = (
            "http://127.0.0.1:5000/api/alerts/"
        )

    def process_packet(
        self,
        timestamp,
        source_ip,
        source_mac,
        target_ip,
        target_mac,
        operation,
        interface="unknown",
        packet_size=42
    ):
        """
        Convert a captured ARP packet into the format
        expected by Person 2's DetectionManager.
        """

        arp_operation = ARPOperation(operation)

        packet = ARPPacket(
            timestamp=timestamp,
            source_ip=source_ip,
            source_mac=source_mac,
            target_ip=target_ip,
            target_mac=target_mac,
            operation=arp_operation,
            interface=interface,
            packet_size=packet_size
        )

        detections = self.manager.process_packet(packet)

        for detection in detections:
            self._send_detection(detection)

        return detections

    def _send_detection(self, detection):
        """
        Send a DetectionResult to the Flask backend.
        """

        payload = detection.to_dict()

        try:

            response = requests.post(
                self.backend_url,
                json=payload,
                timeout=5
            )

            if response.status_code not in (200, 201):

                print(
                    "Backend alert error:",
                    response.status_code,
                    response.text
                )

        except requests.RequestException as error:

            print(
                "Could not send detection to backend:",
                error
            )