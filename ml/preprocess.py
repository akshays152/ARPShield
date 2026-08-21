"""
ARPShield — Preprocessing Module
==================================
Loads the engineered feature dataset, handles missing values, applies
scaling/transformation, and saves the processed dataset along with the
fitted scaler for reproducible preprocessing during prediction.

This module ensures that:
1. Missing values are handled consistently (median imputation).
2. All numerical features are standardized (zero mean, unit variance).
3. The fitted scaler is saved so prediction uses identical transformation.
4. No data leakage: scaler is fit only on training data.

Usage:
    python ml/preprocess.py [--input PATH] [--output PATH] [--scaler-output PATH]
"""

import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler


# Import the canonical feature list from feature engineering
# This ensures train/predict always use the same feature set
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
try:
    from feature_engineering import MODEL_FEATURES
except ImportError:
    # Fallback if import fails (e.g., running from a different directory)
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


def load_features(filepath: str) -> pd.DataFrame:
    """
    Load the engineered feature dataset.

    Parameters
    ----------
    filepath : str
        Path to the features CSV file.

    Returns
    -------
    pd.DataFrame
        Feature DataFrame.
    """
    if not os.path.isfile(filepath):
        print(f"ERROR: Feature file not found: {filepath}")
        sys.exit(1)

    df = pd.read_csv(filepath)

    # Validate that all model features are present
    missing_features = set(MODEL_FEATURES) - set(df.columns)
    if missing_features:
        print(f"ERROR: Missing features in dataset: {missing_features}")
        sys.exit(1)

    return df


def handle_missing_values(df: pd.DataFrame) -> pd.DataFrame:
    """
    Handle missing values in the feature dataset.

    Strategy: Median imputation for numerical features.
    Median is preferred over mean for robustness against outliers,
    which are expected in anomaly detection datasets.

    Parameters
    ----------
    df : pd.DataFrame
        Feature DataFrame.

    Returns
    -------
    pd.DataFrame
        DataFrame with missing values filled.
    """
    missing_counts = df[MODEL_FEATURES].isnull().sum()
    total_missing = missing_counts.sum()

    if total_missing > 0:
        print(f"  Handling {total_missing} missing values (median imputation):")
        for feat in MODEL_FEATURES:
            n_missing = missing_counts[feat]
            if n_missing > 0:
                median_val = df[feat].median()
                df[feat] = df[feat].fillna(median_val)
                print(f"    {feat}: {n_missing} missing → filled with median={median_val:.4f}")
    else:
        print("  No missing values found.")

    return df


def scale_features(
    df: pd.DataFrame,
    scaler: StandardScaler = None,
    fit: bool = True,
) -> tuple[pd.DataFrame, StandardScaler]:
    """
    Apply StandardScaler to numerical features.

    Parameters
    ----------
    df : pd.DataFrame
        Feature DataFrame.
    scaler : StandardScaler, optional
        Pre-fitted scaler (for prediction). If None and fit=True, a new
        scaler is created and fitted.
    fit : bool
        If True, fit the scaler on this data (training). If False, only
        transform using the provided scaler (prediction).

    Returns
    -------
    tuple[pd.DataFrame, StandardScaler]
        Scaled DataFrame and the fitted scaler.
    """
    if scaler is None:
        scaler = StandardScaler()

    feature_data = df[MODEL_FEATURES].values

    if fit:
        scaled_data = scaler.fit_transform(feature_data)
    else:
        scaled_data = scaler.transform(feature_data)

    # Create a new DataFrame with scaled values
    scaled_df = df.copy()
    scaled_df[MODEL_FEATURES] = scaled_data

    return scaled_df, scaler


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Preprocess engineered features for ML training"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("ml", "data", "processed", "features.csv"),
        help="Path to engineered features CSV (default: ml/data/processed/features.csv)",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("ml", "data", "processed", "features_scaled.csv"),
        help="Output path for scaled features (default: ml/data/processed/features_scaled.csv)",
    )
    parser.add_argument(
        "--scaler-output",
        default=os.path.join("ml", "models", "scaler.joblib"),
        help="Output path for fitted scaler (default: ml/models/scaler.joblib)",
    )
    parser.add_argument(
        "--feature-config-output",
        default=os.path.join("ml", "models", "feature_config.json"),
        help="Output path for feature config (default: ml/models/feature_config.json)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Preprocessing")
    print("=" * 60)
    print(f"  Input:          {args.input}")
    print(f"  Output:         {args.output}")
    print(f"  Scaler output:  {args.scaler_output}")
    print()

    # Load features
    print("  Loading engineered features...")
    df = load_features(args.input)
    print(f"  Loaded {len(df)} samples with {len(MODEL_FEATURES)} features")
    print()

    # Handle missing values
    print("  Checking for missing values...")
    df = handle_missing_values(df)
    print()

    # Scale features
    print("  Scaling features (StandardScaler)...")
    scaled_df, scaler = scale_features(df, fit=True)

    # Print scaling parameters
    print("  Scaler parameters:")
    for i, feat in enumerate(MODEL_FEATURES):
        print(f"    {feat:30s}  mean={scaler.mean_[i]:10.4f}  scale={scaler.scale_[i]:10.4f}")
    print()

    # Verify scaled data statistics
    print("  Scaled feature verification (should be ~0 mean, ~1 std):")
    for feat in MODEL_FEATURES:
        vals = scaled_df[feat]
        print(f"    {feat:30s}  mean={vals.mean():8.4f}  std={vals.std():8.4f}")
    print()

    # Save outputs
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    os.makedirs(os.path.dirname(args.scaler_output) if os.path.dirname(args.scaler_output) else ".", exist_ok=True)

    scaled_df.to_csv(args.output, index=False)
    print(f"  Saved scaled features to: {args.output}")

    joblib.dump(scaler, args.scaler_output)
    print(f"  Saved scaler to: {args.scaler_output}")

    # Save feature configuration — critical for prediction consistency
    feature_config = {
        "model_features": MODEL_FEATURES,
        "feature_count": len(MODEL_FEATURES),
        "scaler_type": "StandardScaler",
        "scaler_path": args.scaler_output,
        "note": "Feature order must be preserved during prediction.",
    }
    os.makedirs(os.path.dirname(args.feature_config_output) if os.path.dirname(args.feature_config_output) else ".", exist_ok=True)
    with open(args.feature_config_output, "w", encoding="utf-8") as f:
        json.dump(feature_config, f, indent=2)
    print(f"  Saved feature config to: {args.feature_config_output}")
    print()


if __name__ == "__main__":
    main()
