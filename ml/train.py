"""
ARPShield — Model Training Module
====================================
Trains an Isolation Forest anomaly detection model on preprocessed ARP
network features.

Model Selection Rationale — Isolation Forest:
    1. Unsupervised: Does not require labelled attack data, which is
       unavailable at this stage of the project.
    2. Anomaly-optimised: Explicitly designed for anomaly detection,
       unlike general-purpose clustering methods.
    3. Efficient: O(n·log(n)) training complexity; handles the moderate
       feature space (10 features) effectively.
    4. Interpretable: Anomaly scores provide a continuous measure of
       how "unusual" each observation is, supporting downstream risk
       assessment.
    5. Low false-positive rate: With proper contamination tuning, IF
       provides a good balance between sensitivity and specificity.

Output:
    - Trained model saved as joblib artifact
    - Feature configuration saved as JSON
    - Training summary printed to stdout

Usage:
    python ml/train.py [--input PATH] [--model-output PATH]
                       [--contamination FLOAT] [--n-estimators INT]
                       [--random-state INT]
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


# Import canonical feature list
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
try:
    from feature_engineering import MODEL_FEATURES
except ImportError:
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
        Training data with model features.
    """
    if not os.path.isfile(filepath):
        print(f"ERROR: Training data not found: {filepath}")
        sys.exit(1)

    df = pd.read_csv(filepath)

    # Validate features
    missing = set(MODEL_FEATURES) - set(df.columns)
    if missing:
        print(f"ERROR: Missing features in training data: {missing}")
        sys.exit(1)

    return df


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
        Expected proportion of anomalies in the dataset. Range: (0, 0.5].
        Default 0.05 (5%) is conservative for network anomaly detection.
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
        n_jobs=-1,  # Use all available cores
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
        help="Path to preprocessed features CSV (default: ml/data/processed/features_scaled.csv)",
    )
    parser.add_argument(
        "--model-output",
        default=os.path.join("ml", "models", "isolation_forest.joblib"),
        help="Output path for trained model (default: ml/models/isolation_forest.joblib)",
    )
    parser.add_argument(
        "--config-output",
        default=os.path.join("ml", "models", "feature_config.json"),
        help="Output path for feature config JSON (default: ml/models/feature_config.json)",
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
    X = df[MODEL_FEATURES].values
    print(f"  Training samples: {X.shape[0]}")
    print(f"  Feature count:    {X.shape[1]}")
    print()

    # Validate data quality
    if X.shape[0] < 10:
        print("  WARNING: Very few training samples. Model quality will be limited.")
    if np.any(np.isnan(X)):
        print("  WARNING: NaN values found in training data. These should have been")
        print("  handled during preprocessing. Proceeding anyway.")

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

    n_normal = int(np.sum(predictions == 1))
    n_anomaly = int(np.sum(predictions == -1))
    print("  Training set summary:")
    print(f"    Normal samples:    {n_normal} ({100 * n_normal / len(predictions):.1f}%)")
    print(f"    Anomalous samples: {n_anomaly} ({100 * n_anomaly / len(predictions):.1f}%)")
    print(f"    Anomaly score range: [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"    Anomaly score mean:  {scores.mean():.4f}")
    print(f"    Anomaly score std:   {scores.std():.4f}")
    print()

    # Important disclaimer
    print("  NOTE: These are training-set statistics on synthetic data.")
    print("  They do NOT represent real-world detection performance.")
    print("  Proper evaluation requires real labelled network data.")
    print()

    # Save model
    os.makedirs(os.path.dirname(args.model_output) if os.path.dirname(args.model_output) else ".", exist_ok=True)
    joblib.dump(model, args.model_output)
    print(f"  Saved model to: {args.model_output}")

    # Save/update feature configuration
    feature_config = {
        "model_features": MODEL_FEATURES,
        "feature_count": len(MODEL_FEATURES),
        "model_type": "IsolationForest",
        "contamination": args.contamination,
        "n_estimators": args.n_estimators,
        "random_state": args.random_state,
        "training_samples": int(X.shape[0]),
        "training_duration_seconds": round(train_duration, 3),
        "model_path": args.model_output,
        "scaler_path": os.path.join("ml", "models", "scaler.joblib"),
        "note": (
            "Model trained on synthetic data for pipeline validation. "
            "Not suitable for production security decisions."
        ),
    }
    os.makedirs(os.path.dirname(args.config_output) if os.path.dirname(args.config_output) else ".", exist_ok=True)
    with open(args.config_output, "w", encoding="utf-8") as f:
        json.dump(feature_config, f, indent=2)
    print(f"  Saved feature config to: {args.config_output}")
    print()


if __name__ == "__main__":
    main()
