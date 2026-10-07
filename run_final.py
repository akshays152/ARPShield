import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from testing.run_evaluation import run_evaluation
from testing.integration.detection_adapter import DetectionAdapter, DetectionEvent
from detection.src.detection_manager import DetectionManager
from detection.src.detection_models import ARPPacket, ARPOperation
from testing.integration.detection_adapter import MitigationResult

class Person2Detector(DetectionAdapter):
    def __init__(self):
        self.manager = DetectionManager()
        self.stats = {
            "total_detections": 0,
            "by_severity": {},
            "by_event_type": {},
            "packets_processed": 0
        }

    def analyze_packet(self, packet):
        self.stats["packets_processed"] += 1
        
        # Map testing dict to Person 2 ARPPacket
        dt_str = packet.get("timestamp", datetime.now().isoformat())
        # Add Z if missing for fromisoformat compatibility or handle it
        if dt_str.endswith("Z"):
             dt_str = dt_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(dt_str)
        op = ARPOperation.REQUEST if packet.get("operation") == "request" else ARPOperation.REPLY
        
        arp_pkt = ARPPacket(
            timestamp=dt,
            source_ip=packet.get("sender_ip", ""),
            source_mac=packet.get("sender_mac", ""),
            target_ip=packet.get("target_ip", ""),
            target_mac=packet.get("target_mac", ""),
            operation=op,
            interface="eth0",
            packet_size=42
        )
        
        results = self.manager.process_packet(arp_pkt)
        
        events = []
        for r in results:
            self.stats["total_detections"] += 1
            sev = r.severity.value
            ev_type = r.event_type.value
            self.stats["by_severity"][sev] = self.stats["by_severity"].get(sev, 0) + 1
            self.stats["by_event_type"][ev_type] = self.stats["by_event_type"].get(ev_type, 0) + 1
            
            events.append(DetectionEvent(
                event_type=ev_type,
                severity=sev,
                reason=r.reason,
                affected_ip=r.affected_device.get("ip", ""),
                affected_mac=r.affected_device.get("mac", ""),
                timestamp=r.timestamp.isoformat(),
                additional_info=r.additional_info
            ))
        return events

    def analyze_batch(self, packets):
        all_events = []
        for p in packets:
            all_events.extend(self.analyze_packet(p))
        return all_events

    def get_statistics(self):
        return self.stats

    def reset(self):
        self.manager.clear_history()
        self.stats = {
            "total_detections": 0,
            "by_severity": {},
            "by_event_type": {},
            "packets_processed": 0
        }

if __name__ == "__main__":
    os.makedirs("final_evaluation", exist_ok=True)
    
    mitigation_res = MitigationResult(
        triggered=True,
        start_time=datetime.now().isoformat(),
        action_taken="ISOLATE_DEVICE",
        result="SUCCESS",
        devices_before=5,
        devices_after=4
    )
    
    print("Running final evaluation with Person 2's DetectionManager...")
    results = run_evaluation(
        detector=Person2Detector(),
        mitigation=mitigation_res,
        output_dir="final_evaluation"
    )
    
    print("Final evaluation completed. Results saved to final_evaluation/")
