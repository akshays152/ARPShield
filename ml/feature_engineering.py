"""
ARPShield — Feature Engineering Module
========================================
Converts raw ARP packet observations into a structured, windowed ML dataset.

This module reads per-packet ARP data (as produced by the network monitoring
module) and aggregates it into time-windowed feature vectors suitable for
anomaly detection.

Data Contract (expected input columns):
    - timestamp:  float (Unix epoch seconds)
    - op:         int (1 = ARP request, 2 = ARP reply)
    - src_mac:    string (source MAC address)
    - dst_mac:    string (destination MAC address)
    - src_ip:     string (sender IP address)
    - dst_ip:     string (target IP address)

Output:
    A CSV file where each row represents one time window with the following
    engineered features. See FEATURE_DESCRIPTIONS for full documentation.

Usage:
    python ml/feature_engineering.py [--input PATH] [--output PATH] [--window SECONDS]
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
    "window_start": (
        "Start timestamp (Unix epoch) of the aggregation window. "
        "Used as an index; NOT a model feature."
    ),
    "arp_request_count": (
        "Number of ARP request packets (op=1) observed in the window. "
        "Elevated counts may indicate network scanning or probing."
    ),
    "arp_reply_count": (
        "Number of ARP reply packets (op=2) observed in the window. "
        "An unusually high reply count, especially without corresponding "
        "requests, is a strong indicator of ARP spoofing."
    ),
    "reply_request_ratio": (
        "Ratio of ARP replies to ARP requests in the window "
        "(reply_count / max(request_count, 1)). In normal operation this "
        "ratio stays near 1.0; values significantly above 1.0 suggest "
        "unsolicited replies, a hallmark of ARP cache poisoning."
    ),
    "unique_src_macs": (
        "Number of distinct source MAC addresses seen in the window. "
        "A sudden increase may indicate new devices or MAC spoofing."
    ),
    "unique_src_ips": (
        "Number of distinct source IP addresses in the window. "
        "Helps detect IP spoofing or distributed scanning."
    ),
    "unique_dst_ips": (
        "Number of distinct target IPs queried in the window. "
        "High values indicate network scanning behaviour."
    ),
    "ip_mac_pair_count": (
        "Number of distinct (src_ip, src_mac) pairs in the window. "
        "Instability in IP-MAC mappings is a direct spoofing signal."
    ),
    "max_packets_per_mac": (
        "Maximum number of packets sent by any single MAC in the window. "
        "Concentration of traffic from one MAC can indicate a flood attack."
    ),
    "mac_ip_change_count": (
        "Number of (src_mac, src_ip) pairs where the same MAC address "
        "claims more than one IP, summed across all MACs. Directly "
        "measures MAC-to-IP mapping instability — a primary ARP spoofing "
        "indicator."
    ),
    "unsolicited_reply_ratio": (
        "Estimated ratio of unsolicited ARP replies. Computed as "
        "max(0, reply_count - request_count) / max(total_packets, 1). "
        "This is an approximation since we cannot perfectly match "
        "request-reply pairs without session tracking. Elevated values "
        "indicate potential ARP poisoning."
    ),
}

# Features used by the model (excludes window_start which is metadata)
MODEL_FEATURES = [
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

    Validates that all required columns are present and performs basic
    type coercion. Malformed or incomplete rows are dropped with a warning.

    Parameters
    ----------
    filepath : str
        Path to the CSV file containing raw ARP observations.

    Returns
    -------
    pd.DataFrame
        Cleaned DataFrame with proper types.
    """
    required_columns = {"timestamp", "op", "src_mac", "dst_mac", "src_ip", "dst_ip"}

    if not os.path.isfile(filepath):
        print(f"ERROR: Input file not found: {filepath}")
        sys.exit(1)

    df = pd.read_csv(filepath)

    # Validate columns
    missing = required_columns - set(df.columns)
    if missing:
        print(f"ERROR: Missing required columns: {missing}")
        print(f"  Found columns: {list(df.columns)}")
        print("  Expected: timestamp, op, src_mac, dst_mac, src_ip, dst_ip")
        sys.exit(1)

    original_len = len(df)

    # Coerce types
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
    df["op"] = pd.to_numeric(df["op"], errors="coerce")

    # Drop rows with missing critical fields
    df = df.dropna(subset=["timestamp", "op", "src_mac", "src_ip"])

    # Ensure op is integer
    df["op"] = df["op"].astype(int)

    dropped = original_len - len(df)
    if dropped > 0:
        print(f"  WARNING: Dropped {dropped} malformed/incomplete rows")

    # Sort by timestamp
    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


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
        return {feat: 0 for feat in MODEL_FEATURES}

    requests = window_df[window_df["op"] == 1]
    replies = window_df[window_df["op"] == 2]

    request_count = len(requests)
    reply_count = len(replies)

    # Reply-to-request ratio
    reply_request_ratio = reply_count / max(request_count, 1)

    # Unique entities
    unique_src_macs = window_df["src_mac"].nunique()
    unique_src_ips = window_df["src_ip"].nunique()
    unique_dst_ips = window_df["dst_ip"].nunique()

    # IP-MAC pair instability
    ip_mac_pairs = window_df[["src_ip", "src_mac"]].drop_duplicates()
    ip_mac_pair_count = len(ip_mac_pairs)

    # Max packets from a single MAC
    mac_counts = window_df["src_mac"].value_counts()
    max_packets_per_mac = mac_counts.max() if len(mac_counts) > 0 else 0

    # MAC-IP change count: for each MAC, how many distinct IPs does it claim?
    # Sum (num_ips - 1) across all MACs to get total "changes"
    mac_to_ips = window_df.groupby("src_mac")["src_ip"].nunique()
    mac_ip_change_count = int((mac_to_ips - 1).clip(lower=0).sum())

    # Unsolicited reply ratio (approximation)
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


def engineer_features(
    df: pd.DataFrame, window_seconds: float = 30.0
) -> pd.DataFrame:
    """
    Aggregate raw ARP packet data into time-windowed feature vectors.

    Parameters
    ----------
    df : pd.DataFrame
        Raw ARP packet data with required columns.
    window_seconds : float
        Duration of each aggregation window in seconds.

    Returns
    -------
    pd.DataFrame
        DataFrame where each row is one time window with engineered features.
    """
    if len(df) == 0:
        print("  WARNING: Empty input data — returning empty feature set")
        return pd.DataFrame(columns=["window_start"] + MODEL_FEATURES)

    min_ts = df["timestamp"].min()
    max_ts = df["timestamp"].max()

    # Create window boundaries
    window_starts = np.arange(min_ts, max_ts + window_seconds, window_seconds)

    records = []
    for ws in window_starts:
        we = ws + window_seconds
        window_data = df[(df["timestamp"] >= ws) & (df["timestamp"] < we)]
        features = compute_window_features(window_data)
        features["window_start"] = ws
        records.append(features)

    feature_df = pd.DataFrame(records)

    # Reorder columns: window_start first, then model features
    feature_df = feature_df[["window_start"] + MODEL_FEATURES]

    return feature_df


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Feature Engineering: convert raw ARP data to ML features"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("ml", "data", "sample_arp_data.csv"),
        help="Path to raw ARP packet CSV (default: ml/data/sample_arp_data.csv)",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("ml", "data", "processed", "features.csv"),
        help="Output path for engineered features (default: ml/data/processed/features.csv)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=30.0,
        help="Time window in seconds for feature aggregation (default: 30.0)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Feature Engineering")
    print("=" * 60)
    print(f"  Input:   {args.input}")
    print(f"  Output:  {args.output}")
    print(f"  Window:  {args.window}s")
    print()

    # Load raw data
    print("  Loading raw ARP data...")
    df = load_raw_data(args.input)
    print(f"  Loaded {len(df)} packets")
    print(f"  Time range: {df['timestamp'].min():.1f} — {df['timestamp'].max():.1f}")
    print(f"  Duration: {df['timestamp'].max() - df['timestamp'].min():.1f}s")
    print()

    # Engineer features
    print("  Engineering features...")
    features_df = engineer_features(df, window_seconds=args.window)
    print(f"  Generated {len(features_df)} time windows")
    print()

    # Summary statistics
    print("  Feature summary:")
    for feat in MODEL_FEATURES:
        vals = features_df[feat]
        print(f"    {feat:30s}  mean={vals.mean():8.3f}  std={vals.std():8.3f}  "
              f"min={vals.min():8.3f}  max={vals.max():8.3f}")
    print()

    # Save
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    features_df.to_csv(args.output, index=False)
    print(f"  Saved features to: {args.output}")
    print()

    # Print feature documentation
    print("  Feature Descriptions:")
    for feat in MODEL_FEATURES:
        desc = FEATURE_DESCRIPTIONS.get(feat, "No description available.")
        print(f"    {feat}:")
        # Word-wrap description
        words = desc.split()
        line = "      "
        for word in words:
            if len(line) + len(word) + 1 > 76:
                print(line)
                line = "      " + word
            else:
                line += " " + word if line.strip() else word
        if line.strip():
            print(line)
    print()


if __name__ == "__main__":
    main()
