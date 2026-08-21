"""
ARPShield — Feature Engineering Module
========================================
Converts raw ARP packet observations into a structured ML dataset.

This module reads per-packet ARP data as produced by Person 1's network
monitoring module and engineers features suitable for anomaly detection.

Person 1's Data Format (from network/capture_arp.py):
    - timestamp:   string (ISO datetime, e.g. "2026-08-20 14:52:06")
    - sender_ip:   string (source/sender IP address)
    - sender_mac:  string (source/sender MAC address)
    - target_ip:   string (target IP address)
    - target_mac:  string (target MAC address)
    - operation:   string ("request" or "reply")
    - label:       int (0=normal, 1=attack) — present in final_arp_dataset.csv

The module supports two modes:
    1. Per-packet features: extract features for each individual packet
       (matches Person 1's per-record approach)
    2. Time-windowed features: aggregate packets into time windows
       (complementary approach for temporal pattern detection)

Output:
    A CSV file where each row represents one observation with engineered
    features. See FEATURE_DESCRIPTIONS for full documentation.

Usage:
    python ml/feature_engineering.py [--input PATH] [--output PATH]
                                     [--mode per-packet|windowed]
                                     [--window SECONDS]
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Feature documentation — every engineered feature is described here.
# ---------------------------------------------------------------------------

FEATURE_DESCRIPTIONS = {
    # === Per-packet features ===
    "operation_encoded": (
        "ARP operation type encoded as integer: 0=request, 1=reply. "
        "ARP spoofing attacks predominantly use reply packets."
    ),
    "is_broadcast_target": (
        "Binary flag: 1 if target MAC is broadcast (ff:ff:ff:ff:ff:ff), "
        "0 otherwise. Broadcast targets are normal for ARP requests but "
        "suspicious for unsolicited replies."
    ),
    "is_unspecified_target": (
        "Binary flag: 1 if target IP is 0.0.0.0, 0 otherwise. "
        "Unspecified target IPs appear in ARP probes and announcements."
    ),
    "is_unspecified_sender": (
        "Binary flag: 1 if sender IP is 0.0.0.0, 0 otherwise. "
        "Appears in ARP probes during DHCP; unusual in normal traffic."
    ),
    "macs_per_ip": (
        "Number of distinct MAC addresses associated with this packet's "
        "sender IP across the entire dataset. Values > 1 are a strong "
        "indicator of ARP spoofing (multiple MACs claiming the same IP)."
    ),
    "sender_ip_frequency": (
        "How many times this sender IP appears in the dataset. "
        "Extremely high frequency may indicate flooding or scanning."
    ),
    "hour": (
        "Hour of day (0-23) extracted from the packet timestamp. "
        "Attacks may show temporal patterns (e.g., off-hours activity)."
    ),
    "minute": (
        "Minute of the hour (0-59) from the packet timestamp."
    ),
    "second": (
        "Second of the minute (0-59) from the packet timestamp."
    ),
    "is_reply_with_zero_target": (
        "Binary flag: 1 if the packet is a reply AND the target MAC is "
        "all zeros (00:00:00:00:00:00). This is suspicious because "
        "legitimate ARP replies should have a valid target MAC."
    ),

    # === Windowed features (complementary) ===
    "arp_request_count": (
        "Number of ARP request packets in the time window. "
        "Elevated counts may indicate network scanning or probing."
    ),
    "arp_reply_count": (
        "Number of ARP reply packets in the time window. "
        "Reply floods are a classic ARP spoofing indicator."
    ),
    "reply_request_ratio": (
        "Ratio of replies to requests in the window. "
        "Values >> 1.0 suggest unsolicited replies (ARP poisoning)."
    ),
    "unique_src_macs": (
        "Distinct source MACs in the window. "
        "Sudden increase indicates MAC spoofing."
    ),
    "unique_src_ips": (
        "Distinct source IPs in the window."
    ),
    "unique_dst_ips": (
        "Distinct target IPs in the window. "
        "High values indicate network scanning."
    ),
    "ip_mac_pair_count": (
        "Distinct (IP, MAC) pairs in the window. "
        "Mapping instability is a direct spoofing signal."
    ),
    "max_packets_per_mac": (
        "Max packets from a single MAC in the window."
    ),
    "mac_ip_change_count": (
        "MACs claiming multiple IPs in the window. "
        "Primary ARP spoofing indicator."
    ),
    "unsolicited_reply_ratio": (
        "Estimated unsolicited reply proportion in the window."
    ),
}

# Per-packet features used for primary model (aligns with Person 1's approach)
PER_PACKET_FEATURES = [
    "operation_encoded",
    "is_broadcast_target",
    "is_unspecified_target",
    "is_unspecified_sender",
    "macs_per_ip",
    "sender_ip_frequency",
    "hour",
    "minute",
    "second",
    "is_reply_with_zero_target",
]

# Windowed features (complementary approach)
WINDOWED_FEATURES = [
    "arp_request_count",
    "arp_reply_count",
    "reply_request_ratio",
    "unique_src_macs",
    "unique_src_ips",
    "unique_dst_ips",
    "ip_mac_pair_count",
    "max_packets_per_mac",
    "mac_ip_change_count",
    "unsolicited_reply_ratio",
]


def load_raw_data(filepath: str) -> pd.DataFrame:
    """
    Load raw ARP packet data from CSV.

    Supports Person 1's data format (columns: timestamp, sender_ip,
    sender_mac, target_ip, target_mac, operation) and optionally
    a 'label' column.

    Parameters
    ----------
    filepath : str
        Path to the CSV file containing raw ARP observations.

    Returns
    -------
    pd.DataFrame
        Cleaned DataFrame with proper types.
    """
    required_columns = {"timestamp", "sender_ip", "sender_mac",
                        "target_ip", "target_mac", "operation"}

    if not os.path.isfile(filepath):
        print(f"ERROR: Input file not found: {filepath}")
        sys.exit(1)

    df = pd.read_csv(filepath)

    # Validate columns
    missing = required_columns - set(df.columns)
    if missing:
        print(f"ERROR: Missing required columns: {missing}")
        print(f"  Found columns: {list(df.columns)}")
        print("  Expected: timestamp, sender_ip, sender_mac, "
              "target_ip, target_mac, operation")
        sys.exit(1)

    original_len = len(df)

    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # Drop rows with missing critical fields
    df = df.dropna(subset=["timestamp", "operation", "sender_mac", "sender_ip"])

    dropped = original_len - len(df)
    if dropped > 0:
        print(f"  WARNING: Dropped {dropped} malformed/incomplete rows")

    # Sort by timestamp
    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


def engineer_per_packet_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Engineer per-packet features from raw ARP data.

    This approach aligns with Person 1's feature engineering but adds
    additional security-relevant features. Each row in the output
    corresponds to one ARP packet.

    Parameters
    ----------
    df : pd.DataFrame
        Raw ARP packet data.

    Returns
    -------
    pd.DataFrame
        DataFrame with engineered features.
    """
    result = pd.DataFrame()

    # Operation encoding: request=0, reply=1
    result["operation_encoded"] = df["operation"].map(
        {"request": 0, "reply": 1}
    ).fillna(-1).astype(int)

    # Target MAC flags
    result["is_broadcast_target"] = (
        df["target_mac"].str.lower() == "ff:ff:ff:ff:ff:ff"
    ).astype(int)

    result["is_unspecified_target"] = (
        df["target_ip"] == "0.0.0.0"
    ).astype(int)

    result["is_unspecified_sender"] = (
        df["sender_ip"] == "0.0.0.0"
    ).astype(int)

    # IP-MAC mapping: how many unique MACs per sender IP
    result["macs_per_ip"] = (
        df.groupby("sender_ip")["sender_mac"]
        .transform("nunique")
    )

    # Sender IP frequency
    result["sender_ip_frequency"] = (
        df.groupby("sender_ip")["sender_ip"]
        .transform("count")
    )

    # Time-based features
    result["hour"] = df["timestamp"].dt.hour
    result["minute"] = df["timestamp"].dt.minute
    result["second"] = df["timestamp"].dt.second

    # Suspicious combination: reply with zero target MAC
    result["is_reply_with_zero_target"] = (
        (df["operation"] == "reply") &
        (df["target_mac"] == "00:00:00:00:00:00")
    ).astype(int)

    # Preserve label if present (for evaluation)
    if "label" in df.columns:
        result["label"] = df["label"].values

    return result


def compute_window_features(window_df: pd.DataFrame) -> dict:
    """
    Compute all engineered features for a single time window.

    Parameters
    ----------
    window_df : pd.DataFrame
        Subset of raw data belonging to one time window.

    Returns
    -------
    dict
        Feature dictionary for this window.
    """
    total_packets = len(window_df)

    if total_packets == 0:
        return {feat: 0 for feat in WINDOWED_FEATURES}

    requests = window_df[window_df["operation"] == "request"]
    replies = window_df[window_df["operation"] == "reply"]

    request_count = len(requests)
    reply_count = len(replies)

    reply_request_ratio = reply_count / max(request_count, 1)

    unique_src_macs = window_df["sender_mac"].nunique()
    unique_src_ips = window_df["sender_ip"].nunique()
    unique_dst_ips = window_df["target_ip"].nunique()

    ip_mac_pairs = window_df[["sender_ip", "sender_mac"]].drop_duplicates()
    ip_mac_pair_count = len(ip_mac_pairs)

    mac_counts = window_df["sender_mac"].value_counts()
    max_packets_per_mac = mac_counts.max() if len(mac_counts) > 0 else 0

    mac_to_ips = window_df.groupby("sender_mac")["sender_ip"].nunique()
    mac_ip_change_count = int((mac_to_ips - 1).clip(lower=0).sum())

    excess_replies = max(0, reply_count - request_count)
    unsolicited_reply_ratio = excess_replies / max(total_packets, 1)

    return {
        "arp_request_count": request_count,
        "arp_reply_count": reply_count,
        "reply_request_ratio": round(reply_request_ratio, 6),
        "unique_src_macs": unique_src_macs,
        "unique_src_ips": unique_src_ips,
        "unique_dst_ips": unique_dst_ips,
        "ip_mac_pair_count": ip_mac_pair_count,
        "max_packets_per_mac": max_packets_per_mac,
        "mac_ip_change_count": mac_ip_change_count,
        "unsolicited_reply_ratio": round(unsolicited_reply_ratio, 6),
    }


def engineer_windowed_features(
    df: pd.DataFrame, window_seconds: float = 30.0
) -> pd.DataFrame:
    """
    Aggregate raw ARP packet data into time-windowed feature vectors.

    Parameters
    ----------
    df : pd.DataFrame
        Raw ARP packet data with parsed timestamps.
    window_seconds : float
        Duration of each aggregation window in seconds.

    Returns
    -------
    pd.DataFrame
        DataFrame where each row is one time window.
    """
    if len(df) == 0:
        print("  WARNING: Empty input data — returning empty feature set")
        return pd.DataFrame(columns=["window_start"] + WINDOWED_FEATURES)

    # Convert to numeric timestamp for windowing
    ts = df["timestamp"].astype(np.int64) / 1e9  # nanoseconds to seconds
    min_ts = ts.min()
    max_ts = ts.max()

    window_starts = np.arange(min_ts, max_ts + window_seconds, window_seconds)

    records = []
    for ws in window_starts:
        we = ws + window_seconds
        mask = (ts >= ws) & (ts < we)
        window_data = df[mask]
        features = compute_window_features(window_data)
        features["window_start"] = ws
        records.append(features)

    feature_df = pd.DataFrame(records)
    feature_df = feature_df[["window_start"] + WINDOWED_FEATURES]

    return feature_df


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Feature Engineering: convert raw ARP data to ML features"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("network", "final_arp_dataset.csv"),
        help="Path to raw ARP packet CSV (default: network/final_arp_dataset.csv)",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("ml", "data", "processed", "features.csv"),
        help="Output path for engineered features (default: ml/data/processed/features.csv)",
    )
    parser.add_argument(
        "--mode",
        choices=["per-packet", "windowed"],
        default="per-packet",
        help="Feature engineering mode: per-packet (default) or windowed",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=30.0,
        help="Time window in seconds for windowed mode (default: 30.0)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Feature Engineering")
    print("=" * 60)
    print(f"  Input:   {args.input}")
    print(f"  Output:  {args.output}")
    print(f"  Mode:    {args.mode}")
    if args.mode == "windowed":
        print(f"  Window:  {args.window}s")
    print()

    # Load raw data
    print("  Loading raw ARP data...")
    df = load_raw_data(args.input)
    print(f"  Loaded {len(df)} packets")
    print(f"  Columns: {list(df.columns)}")
    if "label" in df.columns:
        label_counts = df["label"].value_counts()
        print(f"  Labels found: {dict(label_counts)}")
        print(f"    0 (normal): {label_counts.get(0, 0)}")
        print(f"    1 (attack): {label_counts.get(1, 0)}")
    print()

    # Engineer features
    if args.mode == "per-packet":
        print("  Engineering per-packet features...")
        features_df = engineer_per_packet_features(df)
        model_features = PER_PACKET_FEATURES
    else:
        print(f"  Engineering windowed features ({args.window}s windows)...")
        features_df = engineer_windowed_features(df, window_seconds=args.window)
        model_features = WINDOWED_FEATURES

    print(f"  Generated {len(features_df)} feature vectors")
    print(f"  Feature columns: {list(features_df.columns)}")
    print()

    # Summary statistics
    print("  Feature summary:")
    for feat in model_features:
        if feat in features_df.columns:
            vals = features_df[feat]
            print(f"    {feat:30s}  mean={vals.mean():8.3f}  std={vals.std():8.3f}  "
                  f"min={vals.min():8.3f}  max={vals.max():8.3f}")
    print()

    # Save
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    features_df.to_csv(args.output, index=False)
    print(f"  Saved features to: {args.output}")
    print()


if __name__ == "__main__":
    main()
