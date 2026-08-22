"""
ARPShield — Feature Engineering Module
========================================
Converts raw ARP packet observations into a structured ML feature set.

This module reads per-packet ARP data produced by Person 1's network
monitoring module and engineers features for anomaly detection.

LEAKAGE PREVENTION:
    Features that depend on dataset-wide statistics (e.g. macs_per_ip,
    sender_ip_frequency) MUST be computed using the FeatureEngineer class.
    The class separates fit() (called ONLY on training data) from
    transform() (called on any partition). This prevents test-set
    information from leaking into training features.

FEATURE CONFIGURATION:
    All feature selection is controlled via the FEATURE_REGISTRY and
    ENABLED_FEATURES list at the top of this file. To enable/disable
    a feature, add/remove it from ENABLED_FEATURES.

Expected Raw Schema (Person 1's format):
    timestamp    — string (ISO datetime, e.g. "2026-08-20 14:52:06")
    sender_ip    — string
    sender_mac   — string
    target_ip    — string
    target_mac   — string
    operation    — string ("request" or "reply")
    label        — int (0=normal, 1=attack) [optional, for evaluation]

Usage:
    python ml/feature_engineering.py [--input PATH] [--output PATH]
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd


# ===================================================================
# REQUIRED RAW COLUMNS — schema validation
# ===================================================================

REQUIRED_RAW_COLUMNS = {
    "timestamp",
    "sender_ip",
    "sender_mac",
    "target_ip",
    "target_mac",
    "operation",
}

# ===================================================================
# FEATURE REGISTRY — every feature the pipeline knows how to compute
# ===================================================================
# Each entry: (name, description, status)
# status: "enabled", "candidate_removal", or "disabled"

FEATURE_REGISTRY = {
    # --- Core ARP behaviour features (strong candidates) ---
    "operation_encoded": {
        "description": "ARP operation: 0=request, 1=reply.",
        "status": "enabled",
        "category": "arp_behaviour",
        "stateful": False,
        "notes": "Attacks are predominantly replies, but 100% reply rate "
                 "in v1 dataset is a simulation artifact.",
    },
    "macs_per_ip": {
        "description": "Number of distinct MACs associated with the sender "
                       "IP, as learned from the training set.",
        "status": "enabled",
        "category": "ip_mac_mapping",
        "stateful": True,
        "notes": "Primary spoofing indicator. Multiple MACs claiming the "
                 "same IP is a direct ARP poisoning signal. MUST be fit on "
                 "train only to prevent leakage.",
    },
    "sender_ip_frequency": {
        "description": "How many times this sender IP appears in the "
                       "training set.",
        "status": "enabled",
        "category": "frequency",
        "stateful": True,
        "notes": "Flooding/scanning indicator. MUST be fit on train only.",
    },

    # --- Candidate removal features (re-evaluate with v2 data) ---
    "is_broadcast_target": {
        "description": "1 if target MAC is broadcast (ff:ff:ff:ff:ff:ff).",
        "status": "candidate_removal",
        "category": "packet_format",
        "stateful": False,
        "notes": "Ablation showed removing it IMPROVED F1 by +0.10 on v1 "
                 "data. May add noise. Re-evaluate with v2 dataset.",
    },
    "is_unspecified_sender": {
        "description": "1 if sender IP is 0.0.0.0.",
        "status": "candidate_removal",
        "category": "packet_format",
        "stateful": False,
        "notes": "Ablation showed removing it IMPROVED F1 by +0.09 on v1 "
                 "data. Re-evaluate with v2 dataset.",
    },
    "second": {
        "description": "Second of the minute (0-59) from timestamp.",
        "status": "candidate_removal",
        "category": "timing",
        "stateful": False,
        "notes": "Only 25 unique values in v1 data (24-second capture). "
                 "Marginal value. May be useful with longer captures.",
    },
    "is_reply_with_zero_target": {
        "description": "1 if packet is a reply with all-zero target MAC.",
        "status": "candidate_removal",
        "category": "packet_format",
        "stateful": False,
        "notes": "WARNING: SIMULATION ARTIFACT. 90.1% of v1 attacks have "
                 "this flag=1, 0% of normal packets do. This feature was "
                 "created by the attack generation script, not by real ARP "
                 "spoofing. Real replies always have a valid target MAC. "
                 "Ablation shows it is the model's strongest shortcut.",
    },

    # --- Disabled features (zero variance in v1 data) ---
    "hour": {
        "description": "Hour of day (0-23) from timestamp.",
        "status": "disabled",
        "category": "timing",
        "stateful": False,
        "notes": "Zero variance in v1 data (all packets at hour 14). "
                 "May be re-enabled for v2 if capture spans multiple hours.",
    },
    "minute": {
        "description": "Minute of hour (0-59) from timestamp.",
        "status": "disabled",
        "category": "timing",
        "stateful": False,
        "notes": "Zero variance in v1 data (all packets at minute 52).",
    },
    "is_unspecified_target": {
        "description": "1 if target IP is 0.0.0.0.",
        "status": "disabled",
        "category": "packet_format",
        "stateful": False,
        "notes": "Zero variance in v1 data (all zeros).",
    },
}

# ===================================================================
# ENABLED FEATURES — the single source of truth for feature selection
# ===================================================================
# Change this list to enable/disable features for the entire pipeline.
# Features listed here MUST exist in FEATURE_REGISTRY.

ENABLED_FEATURES = [
    "operation_encoded",
    "macs_per_ip",
    "sender_ip_frequency",
    "is_broadcast_target",
    "is_unspecified_sender",
    "second",
    "is_reply_with_zero_target",
]


def validate_feature_config():
    """Assert that ENABLED_FEATURES is a subset of FEATURE_REGISTRY."""
    unknown = set(ENABLED_FEATURES) - set(FEATURE_REGISTRY.keys())
    if unknown:
        raise ValueError(
            f"ENABLED_FEATURES contains unknown features: {unknown}. "
            f"Valid features: {list(FEATURE_REGISTRY.keys())}"
        )
    if len(ENABLED_FEATURES) == 0:
        raise ValueError("ENABLED_FEATURES is empty. At least one feature required.")
    if len(ENABLED_FEATURES) != len(set(ENABLED_FEATURES)):
        raise ValueError("ENABLED_FEATURES contains duplicates.")


# Run validation at import time
validate_feature_config()


def load_raw_data(filepath: str) -> pd.DataFrame:
    """
    Load raw ARP packet data from CSV with strict schema validation.

    Parameters
    ----------
    filepath : str
        Path to the raw ARP CSV file.

    Returns
    -------
    pd.DataFrame
        Cleaned, sorted DataFrame.

    Raises
    ------
    FileNotFoundError
        If filepath does not exist.
    ValueError
        If required columns are missing.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Input file not found: {filepath}")

    df = pd.read_csv(filepath)

    # Schema validation
    missing = REQUIRED_RAW_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            f"Raw data is missing required columns: {missing}. "
            f"Found columns: {list(df.columns)}. "
            f"Expected: {REQUIRED_RAW_COLUMNS}. "
            f"If Person 1 changed the schema in v2, this code must be updated."
        )

    # Parse timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # Drop malformed rows
    original_len = len(df)
    df = df.dropna(subset=["timestamp", "operation", "sender_mac", "sender_ip"])
    dropped = original_len - len(df)
    if dropped > 0:
        print(f"  WARNING: Dropped {dropped} malformed rows")

    # Validate operation values
    valid_ops = {"request", "reply"}
    actual_ops = set(df["operation"].unique())
    unexpected_ops = actual_ops - valid_ops
    if unexpected_ops:
        print(f"  WARNING: Unexpected operation values: {unexpected_ops}")

    # Sort chronologically
    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


class FeatureEngineer:
    """
    Stateful feature engineering to prevent data leakage.

    Features that require dataset-wide statistics (like macs_per_ip,
    sender_ip_frequency) learn their mappings from fit() and apply
    them in transform(). This ensures that when fit() is called on
    training data only, no test-set information leaks.

    Usage:
        engineer = FeatureEngineer()
        train_features = engineer.fit_transform(train_raw_df)
        test_features = engineer.transform(test_raw_df)
    """

    def __init__(self, features: list[str] = None):
        """
        Parameters
        ----------
        features : list[str], optional
            Feature names to compute. Defaults to ENABLED_FEATURES.
        """
        self.features = features if features is not None else ENABLED_FEATURES.copy()
        self.is_fitted = False

        # Stateful mappings (learned from training data)
        self._ip_mac_counts: dict[str, int] = {}
        self._ip_frequencies: dict[str, int] = {}

    def fit(self, df: pd.DataFrame) -> "FeatureEngineer":
        """
        Learn dataset statistics from training data ONLY.

        Parameters
        ----------
        df : pd.DataFrame
            Raw training data (must contain sender_ip, sender_mac).

        Returns
        -------
        self
        """
        assert "sender_ip" in df.columns, "Missing 'sender_ip' column"
        assert "sender_mac" in df.columns, "Missing 'sender_mac' column"

        if "macs_per_ip" in self.features:
            self._ip_mac_counts = (
                df.groupby("sender_ip")["sender_mac"].nunique().to_dict()
            )

        if "sender_ip_frequency" in self.features:
            self._ip_frequencies = (
                df.groupby("sender_ip").size().to_dict()
            )

        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply feature engineering using mappings learned from fit().

        Parameters
        ----------
        df : pd.DataFrame
            Raw data to transform (train or test partition).

        Returns
        -------
        pd.DataFrame
            DataFrame containing only ENABLED_FEATURES columns
            (plus 'label' if present in input).
        """
        assert self.is_fitted, (
            "FeatureEngineer.transform() called before fit(). "
            "Call fit() on training data first."
        )

        result = pd.DataFrame(index=df.index)

        # --- Compute each enabled feature ---
        if "operation_encoded" in self.features:
            result["operation_encoded"] = df["operation"].map(
                {"request": 0, "reply": 1}
            ).fillna(-1).astype(int)

        if "is_broadcast_target" in self.features:
            result["is_broadcast_target"] = (
                df["target_mac"].str.lower() == "ff:ff:ff:ff:ff:ff"
            ).astype(int)

        if "is_unspecified_sender" in self.features:
            result["is_unspecified_sender"] = (
                df["sender_ip"] == "0.0.0.0"
            ).astype(int)

        if "is_unspecified_target" in self.features:
            result["is_unspecified_target"] = (
                df["target_ip"] == "0.0.0.0"
            ).astype(int)

        if "macs_per_ip" in self.features:
            result["macs_per_ip"] = (
                df["sender_ip"].map(self._ip_mac_counts).fillna(1).astype(int)
            )

        if "sender_ip_frequency" in self.features:
            result["sender_ip_frequency"] = (
                df["sender_ip"].map(self._ip_frequencies).fillna(1).astype(int)
            )

        if "hour" in self.features:
            result["hour"] = df["timestamp"].dt.hour

        if "minute" in self.features:
            result["minute"] = df["timestamp"].dt.minute

        if "second" in self.features:
            result["second"] = df["timestamp"].dt.second

        if "is_reply_with_zero_target" in self.features:
            result["is_reply_with_zero_target"] = (
                (df["operation"] == "reply")
                & (df["target_mac"] == "00:00:00:00:00:00")
            ).astype(int)

        # Enforce feature order to guarantee consistency
        output_cols = [f for f in self.features if f in result.columns]
        result = result[output_cols]

        # Preserve label if present (NEVER used as a model feature)
        if "label" in df.columns:
            result["label"] = df["label"].values

        # Assertion: label must NOT appear in the features list
        assert "label" not in self.features, (
            "CRITICAL: 'label' is listed in ENABLED_FEATURES. "
            "This would cause the model to use the answer as input."
        )

        return result

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit on data and then transform it."""
        return self.fit(df).transform(df)

    def get_feature_names(self) -> list[str]:
        """Return the ordered list of feature names this engineer produces."""
        return self.features.copy()


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Feature Engineering"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("network", "final_arp_dataset.csv"),
    )
    parser.add_argument(
        "--output",
        default=os.path.join("ml", "data", "processed", "features.csv"),
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Feature Engineering (Standalone Mode)")
    print("=" * 60)
    print("WARNING: Standalone mode transforms the entire dataset at once.")
    print("This is appropriate ONLY for quick inspection. For strict")
    print("evaluation, use split_and_evaluate.py instead.")
    print()

    df = load_raw_data(args.input)
    print(f"  Loaded {len(df)} packets from {args.input}")

    engineer = FeatureEngineer()
    features_df = engineer.fit_transform(df)
    print(f"  Engineered {len(features_df)} feature vectors")
    print(f"  Features: {engineer.get_feature_names()}")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    features_df.to_csv(args.output, index=False)
    print(f"  Saved to: {args.output}")


if __name__ == "__main__":
    main()
