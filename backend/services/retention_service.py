"""Retention and sampling service for ARP packet logging.

Enforces SQLite database boundaries for a capstone-scale deployment:
1. Normal ARP packet logs are sampled (1-in-N sampling) to prevent database ballooning.
2. Suspicious packets flagged by detection are retained directly.
3. Total ArpPacketLog records are strictly capped (default: 5,000 maximum).
4. Oldest records are automatically pruned when the cap is reached.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from database.database import db
from backend.models.arp_packet_log import ArpPacketLog
from backend.config import Config


class RetentionService:
    """Manages the intake and pruning of ARP packet logs."""

    def __init__(
        self,
        max_records: int = Config.MAX_ARP_PACKET_LOGS,
        sample_rate: int = Config.PACKET_SAMPLE_RATE,
    ):
        self.max_records = max_records
        self.sample_rate = max(1, sample_rate)
        self._packet_counter = 0

    def should_log_packet(
        self, is_suspicious: bool = False, force: bool = False
    ) -> Tuple[bool, str]:
        """Determine whether a packet should be persisted in ArpPacketLog.

        Returns:
            (should_log, log_type): Tuple of bool and 'suspicious' or 'sampled'
        """
        # Suspicious packets are ALWAYS retained directly
        if is_suspicious:
            return True, "suspicious"

        if force:
            return True, "sampled"

        # Normal packets are sampled 1 in sample_rate
        self._packet_counter += 1
        if self._packet_counter % self.sample_rate == 0:
            return True, "sampled"

        return False, ""

    def record_packet(
        self,
        sender_ip: str,
        sender_mac: str,
        target_ip: str,
        target_mac: str,
        operation: str,
        is_gratuitous: bool = False,
        packet_size: int = 42,
        is_suspicious: bool = False,
        force: bool = False,
        timestamp: Optional[datetime] = None,
        auto_trim: bool = True,
    ) -> Optional[ArpPacketLog]:
        """Record an individual ARP packet if it satisfies sampling/suspicion rules."""
        should_log, log_type = self.should_log_packet(is_suspicious=is_suspicious, force=force)
        if not should_log:
            return None

        entry = ArpPacketLog(
            timestamp=timestamp or datetime.utcnow(),
            sender_ip=sender_ip,
            sender_mac=sender_mac,
            target_ip=target_ip,
            target_mac=target_mac,
            operation=operation,
            is_gratuitous=is_gratuitous,
            packet_size=packet_size,
            log_type=log_type,
        )

        db.session.add(entry)
        db.session.commit()

        if auto_trim:
            self.trim_packet_logs()

        return entry

    def record_batch(
        self,
        packets: List[Dict[str, Any]],
        default_suspicious: bool = False,
        auto_trim: bool = True,
    ) -> int:
        """Process and selectively log a batch of captured packets.

        Returns:
            Number of packet logs created in this batch.
        """
        logged_count = 0
        for pkt in packets:
            is_suspicious = pkt.get("is_suspicious", default_suspicious)
            should_log, log_type = self.should_log_packet(is_suspicious=is_suspicious)
            if not should_log:
                continue

            entry = ArpPacketLog(
                timestamp=pkt.get("timestamp") or datetime.utcnow(),
                sender_ip=pkt["sender_ip"],
                sender_mac=pkt["sender_mac"],
                target_ip=pkt["target_ip"],
                target_mac=pkt["target_mac"],
                operation=pkt.get("operation", "request"),
                is_gratuitous=pkt.get("is_gratuitous", False),
                packet_size=pkt.get("packet_size", 42),
                log_type=log_type,
            )
            db.session.add(entry)
            logged_count += 1

        if logged_count > 0:
            db.session.commit()
            if auto_trim:
                self.trim_packet_logs()

        return logged_count

    def trim_packet_logs(self) -> int:
        """Enforces the upper limit on ArpPacketLog.

        Prunes the oldest records when total count exceeds max_records.
        Returns:
            Number of deleted records.
        """
        total = ArpPacketLog.query.count()
        if total <= self.max_records:
            return 0

        excess = total - self.max_records

        # Find IDs of oldest records to prune
        oldest_records = (
            db.session.query(ArpPacketLog.id)
            .order_by(ArpPacketLog.timestamp.asc())
            .limit(excess)
            .all()
        )

        ids_to_delete = [r[0] for r in oldest_records]
        if not ids_to_delete:
            return 0

        deleted_count = ArpPacketLog.query.filter(
            ArpPacketLog.id.in_(ids_to_delete)
        ).delete(synchronize_session=False)

        db.session.commit()
        return deleted_count

    def get_storage_stats(self) -> Dict[str, Any]:
        """Returns storage metrics for the packet log."""
        total = ArpPacketLog.query.count()
        sampled = ArpPacketLog.query.filter_by(log_type="sampled").count()
        suspicious = ArpPacketLog.query.filter_by(log_type="suspicious").count()

        return {
            "total_records": total,
            "sampled_records": sampled,
            "suspicious_records": suspicious,
            "max_records": self.max_records,
            "sample_rate": self.sample_rate,
            "capacity_used_pct": round((total / self.max_records) * 100, 2)
            if self.max_records > 0
            else 0.0,
        }
