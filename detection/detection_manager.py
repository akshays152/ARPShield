"""
Detection Manager for ARP Spoofing Detection
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
import json
import logging
from .detection_models import *
from .rule_engine import RuleEngine

logger = logging.getLogger(__name__)

class DetectionManager:
    """Manages the detection lifecycle and output"""
    
    def __init__(self, gateway_ips: Optional[List[str]] = None):
        self.gateway_ips = set(gateway_ips) if gateway_ips else {'192.168.1.1', '10.0.0.1'}
        self.rule_engine = RuleEngine(self.gateway_ips)
        self.alert_history: List[DetectionResult] = []
        
        self.alert_thresholds = {
            Severity.CRITICAL: {'log': True, 'console': True},
            Severity.HIGH: {'log': True, 'console': True},
            Severity.MEDIUM: {'log': True, 'console': True},
            Severity.LOW: {'log': True, 'console': False}
        }
    
    def process_packet(self, packet: ARPPacket) -> List[DetectionResult]:
        """Process a single ARP packet"""
        try:
            detections = self.rule_engine.process_packet(packet)
            
            for detection in detections:
                self._handle_detection(detection)
            
            return detections
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return []
    
    def process_packets(self, packets: List[ARPPacket]) -> List[DetectionResult]:
        """Process multiple ARP packets"""
        all_detections = []
        for packet in packets:
            detections = self.process_packet(packet)
            all_detections.extend(detections)
        return all_detections
    
    def _handle_detection(self, detection: DetectionResult):
        """Handle a detection result"""
        self.alert_history.append(detection)
        self._log_detection(detection)
        self._alert_if_needed(detection)
    
    def _log_detection(self, detection: DetectionResult):
        """Log detection details"""
        log_level = logging.CRITICAL if detection.severity == Severity.CRITICAL else logging.WARNING
        
        logger.log(
            log_level,
            f"[{detection.event_type.value}] {detection.reason} | Device: {detection.affected_device} | Severity: {detection.severity.value}"
        )
    
    def _alert_if_needed(self, detection: DetectionResult):
        """Trigger alerts based on severity"""
        thresholds = self.alert_thresholds.get(detection.severity, {})
        
        if thresholds.get('console', False):
            print(f"\n🚨 ALERT: {detection.reason}")
            print(f"   Severity: {detection.severity.value}")
            print(f"   Device: {detection.affected_device}\n")
    
    def get_detections(self, 
                      severity: Optional[Severity] = None,
                      event_type: Optional[EventType] = None,
                      limit: Optional[int] = None) -> List[DetectionResult]:
        """Get filtered detections"""
        detections = self.alert_history
        
        if severity:
            detections = [d for d in detections if d.severity == severity]
        if event_type:
            detections = [d for d in detections if d.event_type == event_type]
        if limit:
            detections = detections[-limit:]
        
        return detections
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        stats = {
            'total_detections': len(self.alert_history),
            'by_severity': {},
            'by_event': {},
            'recent_detections': []
        }
        
        for detection in self.alert_history:
            severity = detection.severity.value
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            event = detection.event_type.value
            stats['by_event'][event] = stats['by_event'].get(event, 0) + 1
        
        stats['recent_detections'] = [
            d.to_dict() for d in self.alert_history[-5:]
        ]
        
        return stats
    
    def export_alerts(self, filepath: str = 'arp_detection_alerts.json'):
        """Export alerts to JSON file"""
        alerts_data = [d.to_dict() for d in self.alert_history]
        
        with open(filepath, 'w') as f:
            json.dump({
                'total_alerts': len(alerts_data),
                'timestamp': datetime.now().isoformat(),
                'statistics': self.get_statistics(),
                'alerts': alerts_data
            }, f, indent=2)
        
        logger.info(f"Alerts exported to {filepath}")
    
    def clear_history(self):
        """Clear detection history"""
        self.alert_history.clear()
        self.rule_engine.detections.clear()
        logger.info("Detection history cleared")