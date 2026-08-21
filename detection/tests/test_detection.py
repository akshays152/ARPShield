#!/usr/bin/env python3
"""
Test script for ARP Spoofing Detection Module
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detection_manager import DetectionManager
from tests.mock_data_generator import MockDataGenerator
from src.detection_models import Severity, EventType

def run_tests():
    """Run comprehensive tests on the detection module"""
    
    print("=" * 70)
    print("ARP SPOOFING DETECTION MODULE - TEST SUITE")
    print("=" * 70)
    
    manager = DetectionManager(gateway_ips=['192.168.1.1', '10.0.0.1'])
    generator = MockDataGenerator()
    
    # Test 1: Normal Traffic
    print("\n📊 Test 1: Normal Traffic")
    print("-" * 40)
    normal_packets = generator.generate_normal_traffic(30)
    normal_detections = manager.process_packets(normal_packets)
    print(f"   Packets: {len(normal_packets)}")
    print(f"   Detections: {len(normal_detections)} (Expected: 0)")
    print(f"   Status: {'✅ PASS' if len(normal_detections) == 0 else '❌ FAIL'}")
    
    # Test 2: ARP Spoofing Attack
    print("\n🛡️ Test 2: ARP Spoofing Attack")
    print("-" * 40)
    spoofing_packets = generator.generate_arp_spoofing_attack(15)
    spoofing_detections = manager.process_packets(spoofing_packets)
    gateway_detections = [d for d in spoofing_detections 
                         if d.event_type == EventType.GATEWAY_MAPPING_CHANGE]
    print(f"   Packets: {len(spoofing_packets)}")
    print(f"   Detections: {len(spoofing_detections)}")
    print(f"   Gateway Changes: {len(gateway_detections)}")
    print(f"   Status: {'✅ PASS' if len(gateway_detections) > 0 else '❌ FAIL'}")
    
    # Test 3: Duplicate IP Claims
    print("\n🔍 Test 3: Duplicate IP Claims")
    print("-" * 40)
    duplicate_packets = generator.generate_duplicate_ip_attack(8)
    duplicate_detections = manager.process_packets(duplicate_packets)
    duplicate_events = [d for d in duplicate_detections 
                       if d.event_type == EventType.DUPLICATE_IP_CLAIM]
    print(f"   Packets: {len(duplicate_packets)}")
    print(f"   Detections: {len(duplicate_detections)}")
    print(f"   Duplicate IP Detections: {len(duplicate_events)}")
    print(f"   Status: {'✅ PASS' if len(duplicate_events) > 0 else '❌ FAIL'}")
    
    # Test 4: MAC Flooding
    print("\n🌊 Test 4: MAC Flooding")
    print("-" * 40)
    flood_packets = generator.generate_mac_flooding(100)
    flood_detections = manager.process_packets(flood_packets)
    flood_events = [d for d in flood_detections 
                   if d.event_type in [EventType.MAC_FLOODING, EventType.UNUSUAL_ARP_ACTIVITY]]
    print(f"   Packets: {len(flood_packets)}")
    print(f"   Detections: {len(flood_detections)}")
    print(f"   Flood Detections: {len(flood_events)}")
    print(f"   Status: {'✅ PASS' if len(flood_events) > 0 else '❌ FAIL'}")
    
    # Test 5: Mixed Scenario
    print("\n🎯 Test 5: Mixed Attack Scenario")
    print("-" * 40)
    mixed_packets = generator.generate_mixed_scenario()
    mixed_detections = manager.process_packets(mixed_packets)
    
    by_type = {}
    for d in mixed_detections:
        by_type[d.event_type.value] = by_type.get(d.event_type.value, 0) + 1
    
    print(f"   Total Packets: {len(mixed_packets)}")
    print(f"   Total Detections: {len(mixed_detections)}")
    print(f"   Detections by Type:")
    for event_type, count in by_type.items():
        print(f"      - {event_type}: {count}")
    
    critical_detections = [d for d in mixed_detections if d.severity == Severity.CRITICAL]
    print(f"   Critical Detections: {len(critical_detections)}")
    print(f"   Status: {'✅ PASS' if len(mixed_detections) > 3 else '❌ FAIL'}")
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 TEST SUMMARY")
    print("=" * 70)
    
    stats = manager.get_statistics()
    print(f"\n📈 Overall Detection Statistics:")
    print(f"   Total Detections: {stats['total_detections']}")
    print(f"   By Severity:")
    for severity, count in stats['by_severity'].items():
        print(f"      - {severity}: {count}")
    print(f"   By Event Type:")
    for event, count in stats['by_event'].items():
        print(f"      - {event}: {count}")
    
    manager.export_alerts('test_detection_alerts.json')
    print(f"\n📁 Alerts exported to test_detection_alerts.json")

if __name__ == "__main__":
    run_tests()