"""
Mock data generator for testing ARP detection
"""

from datetime import datetime, timedelta
import random
from src.detection_models import ARPPacket, ARPOperation
from typing import List

class MockDataGenerator:
    """Generates realistic mock ARP data for testing"""
    
    def __init__(self):
        self.base_ips = [f"192.168.1.{i}" for i in range(2, 255)]
        self.gateway_ips = ['192.168.1.1', '10.0.0.1']
        self.trusted_macs = ['AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02']
    
    def generate_normal_traffic(self, count: int = 50) -> List[ARPPacket]:
        """Generate normal ARP traffic"""
        packets = []
        base_time = datetime.now()
        
        for i in range(count):
            source_ip = random.choice(self.base_ips)
            source_mac = random.choice(self.trusted_macs)
            target_ip = random.choice(self.gateway_ips)
            
            packet = ARPPacket(
                timestamp=base_time + timedelta(milliseconds=random.randint(100, 5000)),
                source_ip=source_ip,
                source_mac=source_mac,
                target_ip=target_ip,
                target_mac=None if random.random() > 0.7 else self.trusted_macs[0],
                operation=random.choice([ARPOperation.REQUEST, ARPOperation.REPLY]),
                interface="eth0",
                packet_size=random.randint(42, 60)
            )
            packets.append(packet)
        
        return packets
    
    def generate_arp_spoofing_attack(self, count: int = 10) -> List[ARPPacket]:
        """Generate ARP spoofing attack traffic"""
        packets = []
        base_time = datetime.now()
        attacker_mac = "FF:FF:FF:FF:FF:01"
        victim_ip = "192.168.1.100"
        
        for i in range(count):
            packet = ARPPacket(
                timestamp=base_time + timedelta(milliseconds=100 * i),
                source_ip=random.choice(self.gateway_ips),
                source_mac=attacker_mac,
                target_ip=victim_ip,
                target_mac=random.choice(self.trusted_macs),
                operation=ARPOperation.REPLY,
                interface="eth0",
                packet_size=42
            )
            packets.append(packet)
        
        return packets
    
    def generate_duplicate_ip_attack(self, count: int = 5) -> List[ARPPacket]:
        """Generate duplicate IP claim attack"""
        packets = []
        base_time = datetime.now()
        target_ip = "192.168.1.50"
        
        for i in range(count):
            mac = f"BB:CC:DD:EE:FF:{i:02X}"
            packet = ARPPacket(
                timestamp=base_time + timedelta(milliseconds=100 * i),
                source_ip=target_ip,
                source_mac=mac,
                target_ip=random.choice(self.gateway_ips),
                target_mac=None,
                operation=ARPOperation.REQUEST,
                interface="eth0",
                packet_size=42
            )
            packets.append(packet)
        
        return packets
    
    def generate_mac_flooding(self, count: int = 100) -> List[ARPPacket]:
        """Generate MAC flooding attack"""
        packets = []
        base_time = datetime.now()
        attacker_mac = "EE:EE:EE:EE:EE:01"
        
        for i in range(count):
            target_ip = f"192.168.1.{random.randint(2, 254)}"
            packet = ARPPacket(
                timestamp=base_time + timedelta(milliseconds=10 * i),
                source_ip=f"192.168.1.{random.randint(2, 254)}",
                source_mac=attacker_mac,
                target_ip=target_ip,
                target_mac=None,
                operation=ARPOperation.REQUEST,
                interface="eth0",
                packet_size=42
            )
            packets.append(packet)
        
        return packets
    
    def generate_mixed_scenario(self) -> List[ARPPacket]:
        """Generate a mixed scenario with various attacks"""
        packets = []
        
        packets.extend(self.generate_normal_traffic(30))
        packets.extend(self.generate_duplicate_ip_attack(8))
        packets.extend(self.generate_mac_flooding(60))
        packets.extend(self.generate_arp_spoofing_attack(15))
        
        packets.sort(key=lambda p: p.timestamp)
        
        return packets