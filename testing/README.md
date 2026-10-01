# ARPShield -- Testing, Evaluation & DDoS Impact Analysis (Person 3)

## Purpose

This module provides **cybersecurity testing and evaluation** for the ARPShield detection system. It:

1. Generates controlled test scenarios simulating various ARP spoofing patterns
2. Feeds them through a detection engine via the `DetectionAdapter` interface
3. Evaluates detection accuracy using standard cybersecurity metrics
4. Analyzes the DDoS / network-disruption impact of ARP spoofing
5. Performs before / during / after mitigation comparison
6. Produces machine-readable (JSON/CSV) and human-readable (TXT/Markdown) reports
7. Generates evaluation charts (confusion matrix, rate comparison, etc.)

**No detection logic is implemented here.** Person 2 owns the detection engine.
**No mitigation logic is implemented here.** Person 4 owns the prevention module.
**No offensive network functionality is included.** All testing uses simulated packet data.
Tests must be run only in an authorised, isolated laboratory environment.

> **Important Distinction:**
> ARP spoofing and DDoS are distinct attacks. This module evaluates the
> network disruption / availability impact associated with suspicious ARP
> activity and does not claim that every ARP spoofing event is a DDoS attack.

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
│   ├── detection_metrics.py         # TP/TN/FP/FN, Accuracy, Detection Rate, F1, etc.
│   ├── detection_time.py            # Detection latency analysis
│   ├── false_positive_analysis.py   # Per-rule & per-scenario FP/FN breakdown
│   ├── ddos_impact.py               # Normal vs abnormal vs post-mitigation analysis
│   ├── report_generator.py          # JSON/CSV/TXT/Markdown report generation
│   └── visualize.py                 # Chart generation (matplotlib)
├── integration/
│   ├── __init__.py
│   └── detection_adapter.py         # Abstract interface for Person 2 & 4
├── datasets/
│   └── README.md
└── results/
    └── README.md
```

## Synthetic Data Format

All scenarios generate packets in **Person 1's schema**:

```
timestamp, sender_ip, sender_mac, target_ip, target_mac, operation, label
```

The `label` field is a ground-truth tag used solely for evaluation purposes
(e.g. `normal`, `gateway_spoofing`, `ip_mac_conflict`).
It is not consumed by the detection engine.

### Example normal record

```
timestamp:     2026-09-29T10:00:00
sender_ip:     192.168.1.10
sender_mac:    AA:BB:CC:DD:EE:01
target_ip:     192.168.1.1
target_mac:    AA:BB:CC:DD:EE:FF
operation:     request
label:         normal
```

### Example suspicious record

```
timestamp:     2026-09-29T10:00:02
sender_ip:     192.168.1.1
sender_mac:    AA:BB:CC:DD:EE:99
target_ip:     192.168.1.20
target_mac:    AA:BB:CC:DD:EE:20
operation:     reply
label:         gateway_spoofing
```

## Test Scenarios

| # | Scenario | Expected Detection | Severity | Expected Event Types |
|---|---|---|---|---|
| A | Normal ARP traffic | No | NONE | — |
| B | IP-MAC mapping conflict | Yes | MEDIUM | IP_MAC_MAPPING_CHANGE |
| C | Gateway spoofing | Yes | CRITICAL | GATEWAY_MAPPING_CHANGE |
| D | Duplicate IP claims | Yes | HIGH | DUPLICATE_IP_CLAIM |
| E | Unsolicited ARP replies | Yes | MEDIUM | IP_MAC_MAPPING_CHANGE |
| F | High ARP rate / flood | Yes | HIGH | UNUSUAL_ARP_ACTIVITY, MAC_FLOODING |

Each scenario generates deterministic data using a seeded random generator
so that tests are reproducible.

## Evaluation Metrics

| Metric | Formula | Description |
|---|---|---|
| True Positives (TP) | — | Attack correctly detected |
| True Negatives (TN) | — | Normal traffic correctly not flagged |
| False Positives (FP) | — | Normal traffic incorrectly flagged |
| False Negatives (FN) | — | Attack missed by detection |
| Accuracy | (TP + TN) / total | Overall correctness |
| Detection Rate (Recall) | TP / (TP + FN) | Attack detection sensitivity |
| Precision | TP / (TP + FP) | Detection specificity |
| F1 Score | 2 × P × R / (P + R) | Harmonic mean of Precision and Recall |
| False Positive Rate | FP / (FP + TN) | Rate of false alarms |
| False Negative Rate | FN / (FN + TP) | Rate of missed attacks |

All metrics use safe division to prevent zero-division errors.

## Detection Latency

For every detected attack scenario:

```
detection_latency = detection_timestamp - event_timestamp
```

Reported statistics:
- Minimum latency (ms)
- Maximum latency (ms)
- Average latency (ms)
- Median latency (ms)
- Standard deviation (ms)

When running with StubDetector, no latency data is available
because no detection events are produced. Simulated latency
is clearly marked as synthetic evaluation data.

## False Positive Analysis

Provides per-rule and per-scenario breakdown:
- Number of legitimate scenarios
- Number incorrectly flagged
- False positive rate
- Which detection rule/event type caused each false positive
- Repeated false-positive patterns

## DDoS / Network Impact Analysis

This is the core analytical contribution. It evaluates how
ARP spoofing-related abnormal activity can contribute to:

- Network disruption
- Communication failure
- Service availability degradation
- Excessive ARP traffic
- Host compromise

### Key Metrics

| Metric | Description |
|---|---|
| `normal_arp_rate` | ARP packets/sec during baseline |
| `suspicious_arp_rate` | ARP packets/sec during attack |
| `rate_increase_percent` | % increase in ARP rate |
| `affected_hosts` | Number of unique IPs in suspicious data |
| `suspicious_events` | Count of non-normal packets |
| `attack_duration_seconds` | Duration of abnormal activity |
| `conflicting_mappings` | IPs with multiple MAC addresses |
| `pre_mitigation_disruption` | Disruption score (0.0–1.0) before mitigation |
| `post_mitigation_disruption` | Disruption score after mitigation |
| `improvement_percent` | % disruption reduction after mitigation |

### Phase Comparison Model

```
NORMAL
   ↓
SUSPICIOUS ACTIVITY
   ↓
DETECTION
   ↓
MITIGATION DATA (from Person 4)
   ↓
POST-MITIGATION
```

Each phase is compared on:
- ARP rate (packets per second)
- Suspicious events count
- Affected hosts
- Disruption indicator (0.0–1.0 composite score)

If Person 4's prevention module has not yet supplied post-mitigation data,
the comparison covers only the first two phases, and a note is included
indicating that Person 4's data is pending.

## Report Output

Reports are saved to `testing/results/`:

| Format | File | Description |
|---|---|---|
| JSON | `evaluation_report_*.json` | Machine-readable full report |
| CSV | `scenario_results_*.csv` | Scenario-level results table |
| TXT | `evaluation_summary_*.txt` | Human-readable plain-text summary |
| Markdown | `evaluation_report_*.md` | Human-readable Markdown report |
| JSON | `latest_report.json` | Always-overwritten latest report |

### Charts (if matplotlib available)

| Chart | File |
|---|---|
| ARP rate comparison | `chart_arp_rate_comparison.png` |
| Events by scenario | `chart_events_by_scenario.png` |
| Detection latency | `chart_detection_latency.png` |
| Phase comparison | `chart_mitigation_comparison.png` |
| Confusion matrix | `chart_confusion_matrix.png` |

## How to Run

### Standalone (with stub detector)
```bash
python -m testing.run_evaluation
```

### Unit tests
```bash
python -m pytest tests/test_evaluation_comprehensive.py -v
python -m pytest tests/test_metrics.py tests/test_scenarios.py tests/test_report_generator.py -v
```

### Full test suite (Person 3 only)
```bash
python -m pytest tests/ --ignore=tests/test_person4.py -v
```

## How Person 2 Connects Their Detector

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
   from testing.run_evaluation import run_evaluation
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

4. Additionally, post-mitigation packet data can be supplied to the
   `analyze_ddos_impact()` function directly:
   ```python
   from testing.evaluation.ddos_impact import analyze_ddos_impact
   impact = analyze_ddos_impact(
       normal_data=normal_packets,
       suspicious_data=attack_packets,
       post_mitigation_data=post_mit_packets,
   )
   ```

## Limitations

- All tests use simulated packet data, not live network captures
- Detection timing is measured within the simulation clock
- When using StubDetector, all attack scenarios show as False Negatives
- Person 4 mitigation data may not be available for all runs
- Results should be validated in an authorised, isolated laboratory environment
- ARP spoofing and DDoS are distinct attacks — this module evaluates
  network-disruption impact, not DDoS attribution
- The disruption indicator is a relative metric, not an absolute scale
- Synthetic test results are clearly labelled as "controlled synthetic evaluation"

## Safety

> **WARNING**: All testing in this module uses simulated packet data.
> No real ARP packets are sent, received, or injected.
> No offensive network functionality is included.
> No detection logic is implemented — that is Person 2's responsibility.
> No mitigation logic is implemented — that is Person 4's responsibility.
> Results should be validated in an authorised, isolated laboratory
> environment before drawing production conclusions.
