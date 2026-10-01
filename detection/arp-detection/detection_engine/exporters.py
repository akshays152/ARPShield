import csv
import json
from typing import List
from .events import DetectionEvent


def to_json(events: List[DetectionEvent], path: str) -> None:
    with open(path, "w") as f:
        json.dump([e.to_dict() for e in events], f, indent=2)


def to_csv(events: List[DetectionEvent], path: str) -> None:
    if not events:
        return
    fields = list(events[0].to_dict().keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in events:
            w.writerow(e.to_dict())


def to_markdown(events: List[DetectionEvent], path: str) -> None:
    lines = [
        "| timestamp | rule | severity | affected_ip | affected_mac | reason |",
        "|---|---|---|---|---|---|",
    ]
    for e in events:
        lines.append(
            f"| {e.timestamp} | {e.rule} | {e.severity} | "
            f"{e.affected_ip} | {e.affected_mac} | {e.reason} |"
        )
    with open(path, "w") as f:
        f.write("\n".join(lines))