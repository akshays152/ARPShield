"""
ARPShield — Feature Engineering Module
========================================
Converts raw ARP packet observations into a structured ML dataset.

This module reads per-packet ARP data and engineers features suitable for anomaly detection.

Person 1's Data Format:
    - timestamp:   string (ISO datetime)
    - sender_ip:   string
    - sender_mac:  string
    - target_ip:   string
    - target_mac:  string
    - operation:   string ("request" or "reply")
    - label:       int (0=normal, 1=attack) — present in final_arp_dataset.csv

IMPORTANT LEAKAGE FIX (v2):
    In previous versions, features like `macs_per_ip` and `sender_ip_frequency`
    were computed across the entire dataset, leaking test-set information into
    the training set.
    This module now provides a `FeatureEngineer` class that explicitly separates
    `fit()` (on training data) from `transform()` (on any data) to prevent leakage.

Output:
    A DataFrame/CSV with engineered features.
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Feature documentation
# ---------------------------------------------------------------------------

FEATURE_DESCRIPTIONS = {
    # === Per-packet features ===
    "operation_encoded": "ARP operation: 0=request, 1=reply.",
    "is_broadcast_target": "1 if target MAC is broadcast (ff:ff:ff:ff:ff:ff), else 0.",
    "is_unspecified_sender": "1 if sender IP is 0.0.0.0, else 0.",
    "macs_per_ip": "Number of distinct MACs per sender IP (learned from train set).",
    "sender_ip_frequency": "Frequency of sender IP (learned from train set).",
    "second": "Second of the minute (0-59) from the packet timestamp.",
    "is_reply_with_zero_target": (
        "WARNING (Artefact): 1 if packet is a reply with target MAC all zeros. "
        "This is an artefact of the simulated attack generation script and "
        "not a natural property of ARP spoofing."
    ),
    
    # REMOVED zero-variance features: hour, minute, is_unspecified_target
}

PER_PACKET_FEATURES = [
    "operation_encoded",
    "is_broadcast_target",
    "is_unspecified_sender",
    "macs_per_ip",
    "sender_ip_frequency",
    "second",
    "is_reply_with_zero_target",
]


def load_raw_data(filepath: str) -> pd.DataFrame:
    """Load raw ARP packet data from CSV."""
    if not os.path.isfile(filepath):
        print(f"ERROR: Input file not found: {filepath}")
        sys.exit(1)

    df = pd.read_csv(filepath)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "operation", "sender_mac", "sender_ip"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


class FeatureEngineer:
    """
    Stateful feature engineering to prevent data leakage.
    Learns IP/MAC mappings and frequencies from training data only.
    """
    def __init__(self):
        self.ip_mac_counts = {}
        self.ip_frequencies = {}

    def fit(self, df: pd.DataFrame):
        """Learn mappings from training data."""
        # Learn MACs per IP
        macs_per_ip_series = df.groupby("sender_ip")["sender_mac"].nunique()
        self.ip_mac_counts = macs_per_ip_series.to_dict()

        # Learn IP frequencies
        freq_series = df.groupby("sender_ip").size()
        self.ip_frequencies = freq_series.to_dict()
        
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply feature engineering using learned mappings."""
        result = pd.DataFrame()

        # Operation encoding
        result["operation_encoded"] = df["operation"].map(
            {"request": 0, "reply": 1}
        ).fillna(-1).astype(int)

        # Target MAC flags
        result["is_broadcast_target"] = (
            df["target_mac"].str.lower() == "ff:ff:ff:ff:ff:ff"
        ).astype(int)

        result["is_unspecified_sender"] = (
            df["sender_ip"] == "0.0.0.0"
        ).astype(int)

        # Stateful mappings (default to 1 if unseen IP in test set)
        result["macs_per_ip"] = df["sender_ip"].map(self.ip_mac_counts).fillna(1).astype(int)
        result["sender_ip_frequency"] = df["sender_ip"].map(self.ip_frequencies).fillna(1).astype(int)

        # Time-based features
        result["second"] = df["timestamp"].dt.second

        # Artefact feature
        result["is_reply_with_zero_target"] = (
            (df["operation"] == "reply") &
            (df["target_mac"] == "00:00:00:00:00:00")
        ).astype(int)

        # Preserve label if present
        if "label" in df.columns:
            result["label"] = df["label"].values
            
        # Ensure only expected features are output (plus label)
        cols = PER_PACKET_FEATURES.copy()
        if "label" in result.columns:
            cols.append("label")
        
        return result[cols]

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit and transform in one step."""
        return self.fit(df).transform(df)


def main():
    parser = argparse.ArgumentParser(description="ARPShield — Feature Engineering")
    parser.add_argument("--input", default=os.path.join("network", "final_arp_dataset.csv"))
    parser.add_argument("--output", default=os.path.join("ml", "data", "processed", "features.csv"))
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Feature Engineering (Standalone Mode)")
    print("WARNING: In standalone mode, this transforms the entire dataset at once.")
    print("For strict evaluation, use split_and_evaluate.py instead.")
    print("=" * 60)

    df = load_raw_data(args.input)
    engineer = FeatureEngineer()
    features_df = engineer.fit_transform(df)

    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    features_df.to_csv(args.output, index=False)
    print(f"Saved {len(features_df)} feature vectors to: {args.output}")

if __name__ == "__main__":
    main()
