# ARPShield — Person 4: Risk & Prevention

This module converts detection results into an explainable risk level and
creates administrator-approved defensive response requests.

## Responsibilities

- Combine rule-based findings and Isolation Forest output.
- Produce `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` risk.
- Maintain a trusted-device list.
- Generate JSONL incident logs.
- Create response requests for high/critical incidents.
- Require explicit administrator approval before a response is executed.
- Keep the response layer defensive and lab-safe.

## Risk model

The default score is:

`Risk = 0.60 * RuleScore + 0.40 * MLScore`

If rule-based detection and ML both flag the same event, a +10 correlation
bonus is applied. Trusted devices receive a 10% prioritisation reduction,
but a trusted device never bypasses a strong security finding.

Thresholds:

| Score | Risk |
|---:|---|
| 0–24.99 | LOW |
| 25–49.99 | MEDIUM |
| 50–74.99 | HIGH |
| 75–100 | CRITICAL |

## ML integration

The existing ARPShield ML module produces `anomaly_score` and `is_anomaly`.
Its README explicitly describes these as downstream inputs for a risk engine.

The raw Isolation Forest score is not treated as a percentage. It is mapped
to 0–100 using configurable normal/critical reference points.

## Example

```python
from prevention.service import RiskResponseService

service = RiskResponseService()

result = service.process_event(
    device_mac="aa:bb:cc:dd:ee:ff",
    device_ip="192.168.1.25",
    rule_findings={
        "mac_ip_change": True,
        "unsolicited_reply": 0.8,
        "high_arp_rate": True,
    },
    anomaly_score=-0.22,
    is_anomaly=True,
)

print(result["risk"])
print(result["response_request"])
```

A high/critical result creates a pending `ISOLATE_DEVICE` request. The
request is not executed automatically. An administrator must call:

```python
service.responses.approve("resp-1", "admin")
service.responses.execute("resp-1")
```

The default executor is a dry-run executor. A project-specific authorized
lab integration can replace it with a controlled response adapter.

## Run tests

From the repository root:

```bash
python -m unittest discover -s tests -p "test_person4.py"
```
