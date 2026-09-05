# ARPShield -- Testing, Evaluation & DDoS Impact Analysis (Person 3)

## Purpose

This module provides **cybersecurity testing and evaluation** for the ARPShield detection system. It:

1. Generates controlled test scenarios simulating various ARP spoofing patterns
2. Feeds them through a detection engine via the `DetectionAdapter` interface
3. Evaluates detection accuracy using standard cybersecurity metrics
4. Analyzes the DDoS / network-disruption impact of ARP spoofing
5. Produces machine-readable (JSON/CSV) and human-readable reports

**No detection logic is implemented here.** Person 2 owns the detection engine.
**No offensive network functionality is included.** All testing uses simulated packet data.
Tests must be run only in an authorised, isolated laboratory environment.

## Module Structure

```
testing/
├── __init__.py
├── README.md                        # This file
├── run_evaluation.py                # Main entry point
├── scenarios/
│   ├── __init__.py
│   ├── base.py                      # Base scenario class & lab network constants
│   ├── normal_arp.py                # Scenario A: Normal ARP traffic
│   ├── ip_mac_conflict.py           # Scenario B: IP-MAC mapping conflict
│   ├── gateway_spoofing.py          # Scenario C: Gateway spoofing (CRITICAL)
│   ├── duplicate_ip.py              # Scenario D: Duplicate IP claims
│   ├── suspicious_replies.py        # Scenario E: Unsolicited ARP replies
│   └── high_arp_rate.py             # Scenario F: ARP flood / high rate
├── evaluation/
│   ├── __init__.py
│   ├── detection_metrics.py         # TP/TN/FP/FN, Detection Rate, F1, etc.
│   ├── detection_time.py            # Detection latency analysis
│   ├── false_positive_analysis.py   # Per-rule & per-scenario FP/FN breakdown
│   ├── ddos_impact.py               # Normal vs abnormal traffic comparison
│   └── report_generator.py          # JSON/CSV/TXT report generation
├── integration/
│   ├── __init__.py
│   └── detection_adapter.py         # Abstract interface for Person 2 & 4
├── datasets/
│   └── README.md
└── results/
    └── README.md
```

## Packet Schema

All scenarios generate packets in **Person 1's schema**:

```
timestamp, sender_ip, sender_mac, target_ip, target_mac, operation
```

No detection-engine-specific data models are used.

## Test Scenarios

| # | Scenario | Expected Detection | Severity | Expected Event Types |
|---|---|---|---|---|
| A | Normal ARP traffic | No | NONE | -- |
| B | IP-MAC mapping conflict | Yes | MEDIUM | IP_MAC_MAPPING_CHANGE |
| C | Gateway spoofing | Yes | CRITICAL | GATEWAY_MAPPING_CHANGE |
| D | Duplicate IP claims | Yes | HIGH | DUPLICATE_IP_CLAIM |
| E | Unsolicited ARP replies | Yes | MEDIUM | IP_MAC_MAPPING_CHANGE |
| F | High ARP rate / flood | Yes | HIGH | UNUSUAL_ARP_ACTIVITY, MAC_FLOODING |

## Evaluation Metrics

| Metric | Description |
|---|---|
| True Positives (TP) | Attack correctly detected |
| True Negatives (TN) | Normal traffic correctly not flagged |
| False Positives (FP) | Normal traffic incorrectly flagged |
| False Negatives (FN) | Attack missed by detection |
| Detection Rate | TP / (TP + FN) |
| False Positive Rate | FP / (FP + TN) |
| False Negative Rate | FN / (FN + TP) |
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 Score | Harmonic mean of Precision and Recall |
| Average Detection Time | Mean latency from attack start to detection |
| Min / Max Detection Time | Fastest / slowest detection |

## DDoS Impact Analysis

Compares **normal** vs **abnormal** network conditions:

- ARP packet rate (packets per second)
- ARP request/reply ratio
- Number of suspicious events (from Person 2's detector)
- Number of affected devices
- Attack/event duration
- Detection latency
- Mitigation effectiveness (when Person 4 provides data)

## How to Run

### Standalone (with stub detector)
```bash
python -m testing.run_evaluation
```

### With Person 2's detector connected
```python
from testing.run_evaluation import run_evaluation
from testing.integration.detection_adapter import DetectionAdapter, DetectionEvent

class Person2Detector(DetectionAdapter):
    def analyze_packet(self, packet):
        # ... Person 2's detection logic ...
        return [DetectionEvent(event_type="...", severity="...", reason="...")]

    def analyze_batch(self, packets):
        events = []
        for pkt in packets:
            events.extend(self.analyze_packet(pkt))
        return events

    def get_statistics(self):
        return {"total_detections": ..., "by_severity": {}, "by_event_type": {}}

results = run_evaluation(detector=Person2Detector())
```

### With Person 4's mitigation data
```python
from testing.integration.detection_adapter import MitigationResult

mitigation = MitigationResult(
    triggered=True,
    action_taken="ISOLATE_DEVICE",
    result="Device isolated successfully",
    devices_before=10,
    devices_after=9,
)

results = run_evaluation(detector=my_detector, mitigation=mitigation)
```

### Unit tests
```bash
python -m pytest tests/test_scenarios.py tests/test_metrics.py tests/test_report_generator.py -v
```

## How Person 2 Connects Later

1. Import the adapter interface:
   ```python
   from testing.integration.detection_adapter import DetectionAdapter, DetectionEvent
   ```

2. Create a subclass that wraps Person 2's `RuleEngine` / `DetectionManager`:
   ```python
   class ARPShieldDetector(DetectionAdapter):
       def __init__(self):
           self.engine = RuleEngine(...)  # Person 2's engine

       def analyze_packet(self, packet):
           # Convert Person 1's schema to Person 2's ARPPacket
           arp_pkt = ARPPacket(...)
           results = self.engine.process_packet(arp_pkt)
           # Convert Person 2's DetectionResult to Person 3's DetectionEvent
           return [DetectionEvent(
               event_type=r.event_type.value,
               severity=r.severity.value,
               reason=r.reason,
               affected_ip=r.affected_device.get("ip", ""),
               affected_mac=r.affected_device.get("mac", ""),
           ) for r in results]

       def analyze_batch(self, packets):
           events = []
           for pkt in packets:
               events.extend(self.analyze_packet(pkt))
           return events

       def get_statistics(self):
           return self.engine.get_statistics()
   ```

3. Pass the adapter to `run_evaluation()`:
   ```python
   results = run_evaluation(detector=ARPShieldDetector())
   ```

## How Person 4 Provides Mitigation Data

1. Import the `MitigationResult` dataclass:
   ```python
   from testing.integration.detection_adapter import MitigationResult
   ```

2. Populate it from Person 4's `IncidentLogger` / `ResponseWorkflow`:
   ```python
   mitigation = MitigationResult(
       triggered=True,
       start_time="2026-01-01T00:00:00",
       end_time="2026-01-01T00:00:05",
       action_taken="ISOLATE_DEVICE",
       result="Device isolated",
       devices_before=10,
       devices_after=9,
   )
   ```

3. Pass it to `run_evaluation()`:
   ```python
   results = run_evaluation(detector=..., mitigation=mitigation)
   ```

## Safety & Limitations

> **WARNING**: All testing in this module uses simulated packet data.
> No real ARP packets are sent, received, or injected.
> No offensive network functionality is included.
> No detection logic is implemented -- that is Person 2's responsibility.
> Results should be validated in an authorised, isolated laboratory
> environment before drawing production conclusions.
