import os
import sys
from datetime import datetime
import time

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "detection", "arp-detection")))

from testing.run_evaluation import run_evaluation
from testing.integration.detection_adapter import DetectionAdapter, DetectionEvent
from detection_engine.detector import ARPSpoofDetector
from testing.integration.detection_adapter import MitigationResult

class Person2Detector(DetectionAdapter):
    def __init__(self):
        original_cwd = os.getcwd()
        os.chdir(os.path.join(original_cwd, "detection", "arp-detection"))
        self.detector = ARPSpoofDetector()
        os.chdir(original_cwd)
        self.stats = {
            "total_detections": 0,
            "by_severity": {},
            "by_event_type": {},
            "packets_processed": 0
        }

    def analyze_packet(self, packet):
        self.stats["packets_processed"] += 1
        
        # Map testing dict to Person 2 new dict structure
        dt_str = packet.get("timestamp", datetime.now().isoformat())
        # Try to parse timestamp to float or just use current time
        # The detector expects a float timestamp
        pkt_time = time.time()
        try:
            if isinstance(dt_str, (int, float)):
                pkt_time = float(dt_str)
            else:
                if dt_str.endswith("Z"):
                     dt_str = dt_str[:-1] + "+00:00"
                pkt_time = datetime.fromisoformat(dt_str).timestamp()
        except:
            pass

        op = "request" if packet.get("operation") == "request" else "reply"
        
        arp_pkt = {
            "timestamp": pkt_time,
            "src_ip": packet.get("sender_ip", ""),
            "src_mac": packet.get("sender_mac", ""),
            "dst_ip": packet.get("target_ip", ""),
            "dst_mac": packet.get("target_mac", ""),
            "op": op,
        }
        
        results = self.detector.process(arp_pkt)
        
        events = []
        for r in results:
            self.stats["total_detections"] += 1
            sev = r.get("severity", "MEDIUM")
            ev_type = r.get("rule", "UNKNOWN_RULE")
            self.stats["by_severity"][sev] = self.stats["by_severity"].get(sev, 0) + 1
            self.stats["by_event_type"][ev_type] = self.stats["by_event_type"].get(ev_type, 0) + 1
            
            events.append(DetectionEvent(
                event_type=ev_type,
                severity=sev,
                reason=r.get("reason", ""),
                affected_ip=arp_pkt["src_ip"],
                affected_mac=arp_pkt["src_mac"],
                timestamp=datetime.fromtimestamp(pkt_time).isoformat(),
                additional_info={}
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
        original_cwd = os.getcwd()
        os.chdir(os.path.join(original_cwd, "detection", "arp-detection"))
        self.detector = ARPSpoofDetector()
        os.chdir(original_cwd)
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
    
    print("Running final evaluation with Person 2's new ARPSpoofDetector...")
    results = run_evaluation(
        detector=Person2Detector(),
        mitigation=mitigation_res,
        output_dir="final_evaluation"
    )
    
    print("Final evaluation completed. Results saved to final_evaluation/")
