"""
ARPShield — Preprocessing Module
==================================
Handles missing values and applies StandardScaler normalisation to
engineered features.

LEAKAGE PREVENTION:
    - The scaler MUST be fit on training data only.
    - The scaler MUST then be applied (transform-only) to test data.
    - This module provides scale_features() with explicit fit/transform
      control.
    - The fitted scaler is saved to disk for identical transformation
      during prediction.

Usage (standalone):
    python ml/preprocess.py [--input PATH] [--output PATH]
    WARNING: Standalone mode fits the scaler on the full input. For
    strict evaluation, use split_and_evaluate.py instead.

Programmatic usage:
    from preprocess import scale_features
    X_train_scaled, scaler = scale_features(train_df, features, fit=True)
    X_test_scaled, _       = scale_features(test_df, features, scaler=scaler, fit=False)
"""

import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

# Import the canonical feature list
sys.path.insert(0, os.path.dirname(__file__))
try:
    from feature_engineering import ENABLED_FEATURES
except ImportError:
    ENABLED_FEATURES = []


def handle_missing_values(
    df: pd.DataFrame, features: list[str]
) -> pd.DataFrame:
    """
    Handle missing values via median imputation.

    Median is preferred over mean for robustness against the outliers
    expected in anomaly detection data.

    Parameters
    ----------
    df : pd.DataFrame
        Feature DataFrame.
    features : list[str]
        Feature columns to check.

    Returns
    -------
    pd.DataFrame
        DataFrame with missing values filled.
    """
    missing_counts = df[features].isnull().sum()
    total_missing = missing_counts.sum()

    if total_missing > 0:
        print(f"  Handling {total_missing} missing values (median imputation):")
        for feat in features:
            n_missing = missing_counts[feat]
            if n_missing > 0:
                median_val = df[feat].median()
                df = df.copy()
                df[feat] = df[feat].fillna(median_val)
                print(f"    {feat}: {n_missing} missing -> median={median_val:.4f}")
    else:
        print("  No missing values found.")

    return df


def scale_features(
    df: pd.DataFrame,
    features: list[str],
    scaler: StandardScaler = None,
    fit: bool = True,
) -> tuple[pd.DataFrame, StandardScaler]:
    """
    Apply StandardScaler to numerical features.

    Parameters
    ----------
    df : pd.DataFrame
        Feature DataFrame.
    features : list[str]
        Feature columns to scale.
    scaler : StandardScaler, optional
        Pre-fitted scaler (for prediction/test). If None and fit=True,
        a new scaler is created.
    fit : bool
        If True, fit the scaler on this data (training).
        If False, only transform (prediction/test).

    Returns
    -------
    tuple[pd.DataFrame, StandardScaler]
        (Scaled DataFrame, fitted scaler)
    """
    if scaler is None and not fit:
        raise ValueError(
            "scaler=None with fit=False: cannot transform without a "
            "fitted scaler. Either provide a scaler or set fit=True."
        )

    if scaler is None:
        scaler = StandardScaler()

    feature_data = df[features].values

    if fit:
        scaled_data = scaler.fit_transform(feature_data)
    else:
        # Assertion: feature count must match
        assert feature_data.shape[1] == len(scaler.mean_), (
            f"Feature count mismatch: input has {feature_data.shape[1]} "
            f"features but scaler expects {len(scaler.mean_)}."
        )
        scaled_data = scaler.transform(feature_data)

    scaled_df = df.copy()
    scaled_df[features] = scaled_data

    return scaled_df, scaler


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Preprocess features for ML"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("ml", "data", "processed", "features.csv"),
    )
    parser.add_argument(
        "--output",
        default=os.path.join("ml", "data", "processed", "features_scaled.csv"),
    )
    parser.add_argument(
        "--scaler-output",
        default=os.path.join("ml", "models", "scaler.joblib"),
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Preprocessing (Standalone Mode)")
    print("=" * 60)
    print("WARNING: Standalone mode fits scaler on the full input.")
    print("For strict evaluation, use split_and_evaluate.py instead.")
    print()

    if not os.path.isfile(args.input):
        print(f"ERROR: Feature file not found: {args.input}")
        sys.exit(1)

    df = pd.read_csv(args.input)
    print(f"  Loaded {len(df)} samples")

    features = [f for f in ENABLED_FEATURES if f in df.columns]
    if not features:
        print("ERROR: No enabled features found in input data.")
        sys.exit(1)
    print(f"  Features: {features}")

    df = handle_missing_values(df, features)

    scaled_df, scaler = scale_features(df, features, fit=True)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    scaled_df.to_csv(args.output, index=False)
    print(f"  Saved scaled features to: {args.output}")

    os.makedirs(os.path.dirname(args.scaler_output) or ".", exist_ok=True)
    joblib.dump(scaler, args.scaler_output)
    print(f"  Saved scaler to: {args.scaler_output}")


if __name__ == "__main__":
    main()
