from scapy.all import sniff, ARP
import csv
import requests
from datetime import datetime
from backend.services.detection_service import DetectionService

PACKET_COUNT = 2000
OUTPUT_FILE = "arp_capture_session_5.csv"

# Flask backend
BACKEND_URL = "http://127.0.0.1:5000/api/arp/packets"

# Rule-based ARP detection engine
detection_service = DetectionService(
    gateway_ips=["172.25.160.47"]
)

# Send captured packets to backend in batches
BATCH_SIZE = 100

# Consistent schema for network, ML and backend modules
FIELDS = [
    "timestamp",
    "sender_ip",
    "sender_mac",
    "target_ip",
    "target_mac",
    "operation"
]

data = []


def send_to_backend(packets):
    """
    Send a batch of captured ARP packets to the Flask backend.
    """

    if not packets:
        return

    try:
        response = requests.post(
            BACKEND_URL,
            json={"packets": packets},
            timeout=5
        )

        if response.status_code == 201:
            result = response.json()
            print(
                f"  Backend: received={result.get('received', 0)}, "
                f"logged={result.get('logged', 0)}"
            )
        else:
            print(
                f"  Backend error: HTTP {response.status_code} "
                f"- {response.text}"
            )

    except requests.RequestException as error:
        # Do not stop packet capture if the backend is unavailable
        print(f"  Backend connection failed: {error}")


def capture_packet(packet):
    if packet.haslayer(ARP):

        arp = packet[ARP]

        # Keep operation values consistent
        if arp.op == 1:
            operation = "request"
        elif arp.op == 2:
            operation = "reply"
        else:
            operation = "unknown"

        # Structured ARP record
        record = {
            "timestamp": datetime.fromtimestamp(
                float(packet.time)
            ).strftime("%Y-%m-%d %H:%M:%S"),

            "sender_ip": arp.psrc,
            "sender_mac": arp.hwsrc,
            "target_ip": arp.pdst,
            "target_mac": arp.hwdst,
            "operation": operation
        }

        data.append(record)

        # -----------------------------------------
        # Rule-based detection
        # -----------------------------------------

        try:

            detections = detection_service.process_packet(
                timestamp=datetime.fromtimestamp(
                    float(packet.time)
                ),
                source_ip=arp.psrc,
                source_mac=arp.hwsrc,
                target_ip=arp.pdst,
                target_mac=arp.hwdst,
                operation=operation,
                interface=str(
                    getattr(packet, "sniffed_on", "unknown")
                ),
                packet_size=len(packet)
            )

            if detections:

                print(
                    f"\n🚨 DETECTION: "
                    f"{len(detections)} rule(s) triggered"
                )

                for detection in detections:

                    print(
                        f"   [{detection.severity.value}] "
                        f"{detection.event_type.value}"
                    )

        except Exception as error:

            print(
                f"Detection error: {error}"
            )


        # -----------------------------------------
        # Send every BATCH_SIZE packets to backend
        # -----------------------------------------

        if len(data) % BATCH_SIZE == 0:

            batch = data[-BATCH_SIZE:]

            print(
                f"Captured {len(data)} ARP packets..."
            )

            send_to_backend(batch)

print(
    f"Starting ARP capture. Target: {PACKET_COUNT} packets"
)

print(
    f"Backend integration enabled: {BACKEND_URL}"
)

sniff(
    filter="arp",
    prn=capture_packet,
    store=False,
    count=PACKET_COUNT
)


# Send remaining packets that did not fill a complete batch
remaining = len(data) % BATCH_SIZE

if remaining:
    print(
        f"Sending final {remaining} packets to backend..."
    )

    send_to_backend(data[-remaining:])


# Save structured output
with open(
    OUTPUT_FILE,
    "w",
    newline=""
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=FIELDS
    )

    writer.writeheader()
    writer.writerows(data)


print("\nCapture complete!")
print(f"Total ARP packets captured: {len(data)}")
print(f"Dataset saved as: {OUTPUT_FILE}")
print("Output schema:", ", ".join(FIELDS))