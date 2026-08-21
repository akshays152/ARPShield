"""
Rule Engine for ARP Spoofing Detection
"""

from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
from .detection_models import *

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DetectionRule:
    """Base class for detection rules"""
    
    def __init__(self, name: str, severity: Severity):
        self.name = name
        self.severity = severity
        
    def check(self, packet: ARPPacket, context: Dict) -> Optional[DetectionResult]:
        """Check if rule is triggered - to be overridden"""
        raise NotImplementedError

class IPMACChangeRule(DetectionRule):
    """Rule 1: Detects unexpected IP-MAC mapping changes"""
    
    def __init__(self):
        super().__init__("IP-MAC Change Detection", Severity.MEDIUM)
        self.max_changes_per_minute = 3
        self.time_window = 60
        
    def check(self, packet: ARPPacket, context: Dict) -> Optional[DetectionResult]:
        ip_mac_mapping = context.get('ip_mac_mapping', {})
        
        if packet.source_ip in ip_mac_mapping:
            existing = ip_mac_mapping[packet.source_ip]
            
            if existing.current_mac != packet.source_mac:
                recent_changes = [
                    change for change in existing.mac_history
                    if (datetime.now() - change['timestamp']).total_seconds() < self.time_window
                ]
                
                if len(recent_changes) >= self.max_changes_per_minute:
                    return DetectionResult(
                        detection_id="",
                        event_type=EventType.ARP_SPOOFING_ATTACK,
                        severity=Severity.CRITICAL,
                        reason=f"Rapid MAC changes detected for IP {packet.source_ip}: {len(recent_changes)} changes in {self.time_window}s",
                        affected_device={'ip': packet.source_ip, 'mac': packet.source_mac},
                        timestamp=datetime.now(),
                        source_packet=packet,
                        additional_info={
                            'previous_mac': existing.current_mac,
                            'change_count': len(recent_changes),
                            'change_history': recent_changes[-5:]
                        }
                    )
                else:
                    return DetectionResult(
                        detection_id="",
                        event_type=EventType.IP_MAC_MAPPING_CHANGE,
                        severity=Severity.MEDIUM,
                        reason=f"MAC change for IP {packet.source_ip}: {existing.current_mac} -> {packet.source_mac}",
                        affected_device={'ip': packet.source_ip, 'mac': packet.source_mac},
                        timestamp=datetime.now(),
                        source_packet=packet,
                        additional_info={
                            'previous_mac': existing.current_mac,
                            'new_mac': packet.source_mac,
                            'change_number': len(existing.mac_history) + 1
                        }
                    )
        return None

class DuplicateIPClaimRule(DetectionRule):
    """Rule 2: Detects duplicate IP claims by different MAC addresses"""
    
    def __init__(self):
        super().__init__("Duplicate IP Claim Detection", Severity.HIGH)
        self.min_claims_for_alert = 3
        self.time_window = 60
        
    def check(self, packet: ARPPacket, context: Dict) -> Optional[DetectionResult]:
        ip_claims = context.get('ip_claims', {})
        
        if packet.source_ip in ip_claims:
            claims = ip_claims[packet.source_ip]
            
            mac_groups = defaultdict(list)
            for claim in claims:
                if (datetime.now() - claim.timestamp).total_seconds() < self.time_window:
                    mac_groups[claim.source_mac].append(claim)
            
            unique_macs = list(mac_groups.keys())
            if len(unique_macs) >= self.min_claims_for_alert:
                severity = Severity.CRITICAL if len(unique_macs) >= 5 else Severity.HIGH
                
                return DetectionResult(
                    detection_id="",
                    event_type=EventType.DUPLICATE_IP_CLAIM,
                    severity=severity,
                    reason=f"IP {packet.source_ip} claimed by {len(unique_macs)} different MACs: {', '.join(unique_macs[:3])}...",
                    affected_device={'ip': packet.source_ip, 'mac': packet.source_mac},
                    timestamp=datetime.now(),
                    source_packet=packet,
                    additional_info={
                        'claiming_macs': unique_macs,
                        'total_claims': len(claims),
                        'claims_per_mac': {mac: len(macs) for mac, macs in mac_groups.items()}
                    }
                )
        return None

class GatewayChangeRule(DetectionRule):
    """Rule 3: Monitors gateway MAC changes with high priority"""
    
    def __init__(self, gateway_ips: Set[str]):
        super().__init__("Gateway Change Detection", Severity.CRITICAL)
        self.gateway_ips = gateway_ips
        self.gateway_mac_history: Dict[str, List[Tuple[str, datetime]]] = defaultdict(list)
        
    def check(self, packet: ARPPacket, context: Dict) -> Optional[DetectionResult]:
        if packet.source_ip not in self.gateway_ips:
            return None
            
        ip_mac_mapping = context.get('ip_mac_mapping', {})
        
        if packet.source_ip in ip_mac_mapping:
            existing = ip_mac_mapping[packet.source_ip]
            
            if existing.current_mac != packet.source_mac:
                self.gateway_mac_history[packet.source_ip].append(
                    (packet.source_mac, datetime.now())
                )
                
                return DetectionResult(
                    detection_id="",
                    event_type=EventType.GATEWAY_MAPPING_CHANGE,
                    severity=Severity.CRITICAL,
                    reason=f"🚨 GATEWAY ATTACK: Gateway {packet.source_ip} MAC changed from {existing.current_mac} to {packet.source_mac}",
                    affected_device={'ip': packet.source_ip, 'mac': packet.source_mac},
                    timestamp=datetime.now(),
                    source_packet=packet,
                    additional_info={
                        'previous_mac': existing.current_mac,
                        'new_mac': packet.source_mac,
                        'is_arp_spoofing': True,
                        'gateway_history': self.gateway_mac_history[packet.source_ip][-5:]
                    }
                )
        return None

class UnusualARPActivityRule(DetectionRule):
    """Rule 4: Detects unusual ARP activity patterns"""
    
    def __init__(self):
        super().__init__("Unusual ARP Activity", Severity.HIGH)
        self.max_arp_rate = 50
        self.flood_threshold = 100
        
    def check(self, packet: ARPPacket, context: Dict) -> Optional[DetectionResult]:
        arp_rate = context.get('arp_rate', {})
        
        if packet.source_mac not in arp_rate:
            arp_rate[packet.source_mac] = deque(maxlen=200)
        
        arp_rate[packet.source_mac].append(packet.timestamp)
        
        cutoff = datetime.now() - timedelta(minutes=1)
        recent = [t for t in arp_rate[packet.source_mac] if t > cutoff]
        
        if len(recent) > self.max_arp_rate:
            severity = Severity.CRITICAL if len(recent) > self.flood_threshold else Severity.HIGH
            event_type = EventType.MAC_FLOODING if len(recent) > self.flood_threshold else EventType.UNUSUAL_ARP_ACTIVITY
            
            return DetectionResult(
                detection_id="",
                event_type=event_type,
                severity=severity,
                reason=f"Abnormal ARP rate from {packet.source_mac}: {len(recent)} packets in last minute",
                affected_device={'ip': packet.source_ip, 'mac': packet.source_mac},
                timestamp=datetime.now(),
                source_packet=packet,
                additional_info={
                    'packet_count': len(recent),
                    'threshold': self.max_arp_rate,
                    'is_flood': len(recent) > self.flood_threshold,
                    'time_window': 60
                }
            )
        return None

class ARPRequestStormRule(DetectionRule):
    """Rule 5: Detects ARP request storms targeting multiple IPs"""
    
    def __init__(self):
        super().__init__("ARP Request Storm", Severity.HIGH)
        self.unique_targets_threshold = 20
        self.time_window = 30
        
    def check(self, packet: ARPPacket, context: Dict) -> Optional[DetectionResult]:
        if packet.operation != ARPOperation.REQUEST:
            return None
            
        arp_request_history = context.get('arp_request_history', {})
        
        if packet.source_mac not in arp_request_history:
            arp_request_history[packet.source_mac] = deque(maxlen=100)
        
        arp_request_history[packet.source_mac].append({
            'target_ip': packet.target_ip,
            'timestamp': packet.timestamp
        })
        
        cutoff = datetime.now() - timedelta(seconds=self.time_window)
        recent_requests = [r for r in arp_request_history[packet.source_mac] 
                          if r['timestamp'] > cutoff]
        
        unique_targets = set(r['target_ip'] for r in recent_requests)
        
        if len(unique_targets) > self.unique_targets_threshold:
            return DetectionResult(
                detection_id="",
                event_type=EventType.ARP_REQUEST_STORM,
                severity=Severity.HIGH,
                reason=f"ARP scanning detected from {packet.source_mac}: scanning {len(unique_targets)} unique IPs in {self.time_window}s",
                affected_device={'ip': packet.source_ip, 'mac': packet.source_mac},
                timestamp=datetime.now(),
                source_packet=packet,
                additional_info={
                    'unique_targets': len(unique_targets),
                    'total_requests': len(recent_requests),
                    'target_ips': list(unique_targets)[:10],
                    'time_window': self.time_window
                }
            )
        return None

class RuleEngine:
    """Main rule engine that applies all detection rules"""
    
    def __init__(self, gateway_ips: Optional[Set[str]] = None):
        self.gateway_ips = gateway_ips or {'192.168.1.1', '10.0.0.1'}
        
        self.rules = [
            IPMACChangeRule(),
            DuplicateIPClaimRule(),
            GatewayChangeRule(self.gateway_ips),
            UnusualARPActivityRule(),
            ARPRequestStormRule()
        ]
        
        self.context = {
            'ip_mac_mapping': {},
            'ip_claims': defaultdict(list),
            'arp_rate': defaultdict(deque),
            'arp_request_history': defaultdict(deque)
        }
        
        self.detections: List[DetectionResult] = []
        
    def process_packet(self, packet: ARPPacket) -> List[DetectionResult]:
        """Process a packet through all rules"""
        detections = []
        
        self._update_context(packet)
        
        for rule in self.rules:
            try:
                result = rule.check(packet, self.context)
                if result:
                    detections.append(result)
                    self.detections.append(result)
                    logger.warning(f"Rule triggered: {rule.name} - {result.reason}")
            except Exception as e:
                logger.error(f"Error in rule {rule.name}: {e}")
        
        return detections
    
    def _update_context(self, packet: ARPPacket):
        """Update the context with packet information"""
        if packet.source_ip in self.context['ip_mac_mapping']:
            existing = self.context['ip_mac_mapping'][packet.source_ip]
            if existing.current_mac != packet.source_mac:
                existing.mac_history.append({
                    'mac': existing.current_mac,
                    'timestamp': datetime.now()
                })
                existing.current_mac = packet.source_mac
                existing.change_count += 1
                existing.last_change_time = datetime.now()
            existing.last_seen = datetime.now()
            existing.packet_count += 1
            if packet.operation == ARPOperation.REPLY:
                existing.reply_count += 1
            else:
                existing.request_count += 1
        else:
            self.context['ip_mac_mapping'][packet.source_ip] = ARPMapping(
                ip=packet.source_ip,
                current_mac=packet.source_mac,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                is_gateway=packet.source_ip in self.gateway_ips
            )
        
        self.context['ip_claims'][packet.source_ip].append(packet)
        
        if packet.source_mac not in self.context['arp_rate']:
            self.context['arp_rate'][packet.source_mac] = deque(maxlen=200)
        self.context['arp_rate'][packet.source_mac].append(packet.timestamp)
        
        if packet.operation == ARPOperation.REQUEST:
            if packet.source_mac not in self.context['arp_request_history']:
                self.context['arp_request_history'][packet.source_mac] = deque(maxlen=100)
            self.context['arp_request_history'][packet.source_mac].append({
                'target_ip': packet.target_ip,
                'timestamp': packet.timestamp
            })
    
    def get_detections(self, 
                      severity: Optional[Severity] = None,
                      event_type: Optional[EventType] = None,
                      time_window: Optional[int] = None) -> List[DetectionResult]:
        """Retrieve detections with filters"""
        results = self.detections
        
        if severity:
            results = [d for d in results if d.severity == severity]
        if event_type:
            results = [d for d in results if d.event_type == event_type]
        if time_window:
            cutoff = datetime.now() - timedelta(seconds=time_window)
            results = [d for d in results if d.timestamp > cutoff]
        
        return results