"""
ARPShield — Model Training Module
====================================
Trains an Isolation Forest anomaly detection model on preprocessed ARP
network features.

This module now works with Person 1's actual captured ARP data, which
includes 5,000 normal packets and 1,000 simulated attack packets with
labels (0=normal, 1=attack).

Model Selection Rationale — Isolation Forest:
    1. Anomaly-optimised: Explicitly designed for anomaly detection,
       isolating anomalies via random partitioning (shorter path = anomaly).
    2. Handles mixed training: Can be trained on mostly-normal data
       without explicit labels, or can be evaluated against labels.
    3. Efficient: O(n*log(n)) training; handles the feature space well.
    4. Interpretable: Anomaly scores provide continuous measure of how
       "unusual" each observation is.
    5. Low false-positive rate with proper contamination tuning.

Usage:
    python ml/train.py [--input PATH] [--model-output PATH]
                       [--contamination FLOAT] [--n-estimators INT]
"""

import argparse
import json
import os
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


# Import canonical feature lists
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
try:
    from feature_engineering import PER_PACKET_FEATURES, WINDOWED_FEATURES
except ImportError:
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


def load_training_data(filepath: str) -> pd.DataFrame:
    """
    Load preprocessed (scaled) feature data for training.

    Parameters
    ----------
    filepath : str
        Path to the scaled features CSV.

    Returns
    -------
    pd.DataFrame
        Training data.
    """
    if not os.path.isfile(filepath):
        print(f"ERROR: Training data not found: {filepath}")
        sys.exit(1)

    df = pd.read_csv(filepath)
    return df


def detect_features(df: pd.DataFrame) -> list[str]:
    """
    Detect which feature set is present in the data.

    Returns
    -------
    list[str]
        Feature column names.
    """
    pp_missing = set(PER_PACKET_FEATURES) - set(df.columns)
    w_missing = set(WINDOWED_FEATURES) - set(df.columns)

    if len(pp_missing) == 0:
        return PER_PACKET_FEATURES
    elif len(w_missing) == 0:
        return WINDOWED_FEATURES
    else:
        # Use feature_config if available
        config_path = os.path.join("ml", "models", "feature_config.json")
        if os.path.isfile(config_path):
            with open(config_path, "r") as f:
                config = json.load(f)
            return config.get("model_features", PER_PACKET_FEATURES)
        return [f for f in PER_PACKET_FEATURES if f in df.columns]


def train_isolation_forest(
    X: np.ndarray,
    contamination: float = 0.05,
    n_estimators: int = 100,
    random_state: int = 42,
) -> IsolationForest:
    """
    Train an Isolation Forest model.

    Parameters
    ----------
    X : np.ndarray
        Training feature matrix (n_samples, n_features).
    contamination : float
        Expected proportion of anomalies in the dataset.
    n_estimators : int
        Number of isolation trees in the ensemble.
    random_state : int
        Random seed for reproducibility.

    Returns
    -------
    IsolationForest
        Fitted model.
    """
    model = IsolationForest(
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
    )

    model.fit(X)
    return model


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Train Isolation Forest anomaly detection model"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("ml", "data", "processed", "features_scaled.csv"),
        help="Path to preprocessed features CSV",
    )
    parser.add_argument(
        "--model-output",
        default=os.path.join("ml", "models", "isolation_forest.joblib"),
        help="Output path for trained model",
    )
    parser.add_argument(
        "--config-output",
        default=os.path.join("ml", "models", "feature_config.json"),
        help="Output path for feature config JSON",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Expected anomaly proportion (default: 0.05)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of isolation trees (default: 100)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Model Training (Isolation Forest)")
    print("=" * 60)
    print(f"  Input:          {args.input}")
    print(f"  Model output:   {args.model_output}")
    print(f"  Contamination:  {args.contamination}")
    print(f"  N estimators:   {args.n_estimators}")
    print(f"  Random state:   {args.random_state}")
    print()

    # Load data
    print("  Loading preprocessed features...")
    df = load_training_data(args.input)

    # Detect features
    features = detect_features(df)
    print(f"  Features ({len(features)}): {features}")

    X = df[features].values
    print(f"  Training samples: {X.shape[0]}")
    print(f"  Feature count:    {X.shape[1]}")

    # Report labels if present
    has_labels = "label" in df.columns
    if has_labels:
        label_counts = df["label"].value_counts()
        print(f"  Labels present: {dict(label_counts)}")
        print(f"    Normal (0): {label_counts.get(0, 0)}")
        print(f"    Attack (1): {label_counts.get(1, 0)}")
    print()

    # Validate data quality
    if X.shape[0] < 10:
        print("  WARNING: Very few training samples. Model quality will be limited.")
    nan_count = int(np.isnan(X).sum())
    if nan_count > 0:
        print(f"  WARNING: {nan_count} NaN values found in training data.")

    # Train model
    print("  Training Isolation Forest...")
    start_time = time.time()
    model = train_isolation_forest(
        X,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
    )
    train_duration = time.time() - start_time
    print(f"  Training completed in {train_duration:.3f}s")
    print()

    # Generate training predictions for summary
    predictions = model.predict(X)
    scores = model.decision_function(X)

    # Isolation Forest outputs: 1 = normal (inlier), -1 = anomaly (outlier)
    n_normal = int(np.sum(predictions == 1))
    n_anomaly = int(np.sum(predictions == -1))

    print("  Training set prediction summary:")
    print(f"    Predicted normal:    {n_normal} ({100 * n_normal / len(predictions):.1f}%)")
    print(f"    Predicted anomalous: {n_anomaly} ({100 * n_anomaly / len(predictions):.1f}%)")
    print(f"    Anomaly score range: [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"    Anomaly score mean:  {scores.mean():.4f}")
    print(f"    Anomaly score std:   {scores.std():.4f}")

    # If labels exist, show agreement between predictions and labels
    if has_labels:
        labels = df["label"].values
        # Convert: label 1 (attack) should map to prediction -1 (anomaly)
        pred_anomaly = predictions == -1
        label_anomaly = labels == 1

        true_pos = int(np.sum(pred_anomaly & label_anomaly))
        false_pos = int(np.sum(pred_anomaly & ~label_anomaly))
        true_neg = int(np.sum(~pred_anomaly & ~label_anomaly))
        false_neg = int(np.sum(~pred_anomaly & label_anomaly))

        print()
        print("  Training set vs. labels (informational only):")
        print(f"    True Positives:  {true_pos} (attacks correctly flagged)")
        print(f"    False Positives: {false_pos} (normal flagged as anomaly)")
        print(f"    True Negatives:  {true_neg} (normal correctly passed)")
        print(f"    False Negatives: {false_neg} (attacks missed)")
        print()
        print("  NOTE: These are training-set statistics, not test performance.")

    print()

    # Save model
    os.makedirs(os.path.dirname(args.model_output) if os.path.dirname(args.model_output) else ".", exist_ok=True)
    joblib.dump(model, args.model_output)
    print(f"  Saved model to: {args.model_output}")

    # Save feature configuration
    feature_config = {
        "model_features": features,
        "feature_count": len(features),
        "model_type": "IsolationForest",
        "contamination": args.contamination,
        "n_estimators": args.n_estimators,
        "random_state": args.random_state,
        "training_samples": int(X.shape[0]),
        "training_duration_seconds": round(train_duration, 3),
        "has_labels": has_labels,
        "model_path": args.model_output,
        "scaler_path": os.path.join("ml", "models", "scaler.joblib"),
        "data_source": "network/final_arp_dataset.csv (Person 1's captured data)",
    }
    os.makedirs(os.path.dirname(args.config_output) if os.path.dirname(args.config_output) else ".", exist_ok=True)
    with open(args.config_output, "w", encoding="utf-8") as f:
        json.dump(feature_config, f, indent=2)
    print(f"  Saved feature config to: {args.config_output}")
    print()


if __name__ == "__main__":
    main()
