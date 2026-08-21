"""Append-only JSONL incident logger."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict


class IncidentLogger:
    def __init__(self, path: str = "prevention/incidents.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        incident_type: str,
        severity: str,
        details: Dict[str, Any],
        source: str = "ARPShield",
    ) -> Dict[str, Any]:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "incident_type": incident_type,
            "severity": severity,
            "details": details,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
