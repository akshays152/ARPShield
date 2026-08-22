"""
ARPShield — Model Training Module
====================================
Trains an Isolation Forest anomaly detection model on preprocessed
ARP network features.

IMPORTANT — Isolation Forest is UNSUPERVISED:
    The model does not use labels during training. If labels are present
    in the dataset, they are used ONLY for informational diagnostics on
    the training set (not for fitting the model).

Reproducibility:
    - Random seed is configurable via --random-state.
    - All model parameters, feature names, and training metadata are
      saved alongside the model in a JSON metadata file.
    - The scaler, feature_engineer state, and model are all saved so
      that predict.py can reconstruct the exact pipeline.

Usage:
    python ml/train.py [--input PATH] [--model-output PATH]
                       [--contamination FLOAT] [--n-estimators INT]
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# Import canonical feature list
sys.path.insert(0, os.path.dirname(__file__))
try:
    from feature_engineering import ENABLED_FEATURES
except ImportError:
    ENABLED_FEATURES = []


def train_isolation_forest(
    X: np.ndarray,
    contamination: float = 0.05,
    n_estimators: int = 100,
    random_state: int = 42,
) -> IsolationForest:
    """
    Train an Isolation Forest model.

    The model is UNSUPERVISED — it learns the structure of the data
    and isolates anomalies via random partitioning. Labels are NOT used.

    Parameters
    ----------
    X : np.ndarray
        Training feature matrix (n_samples, n_features).
    contamination : float
        Expected proportion of anomalies (0 < contamination <= 0.5).
    n_estimators : int
        Number of isolation trees.
    random_state : int
        Random seed.

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
        description="ARPShield — Train Isolation Forest"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("ml", "data", "processed", "features_scaled.csv"),
        help="Preprocessed (scaled) features CSV",
    )
    parser.add_argument(
        "--model-output",
        default=os.path.join("ml", "models", "isolation_forest.joblib"),
    )
    parser.add_argument(
        "--metadata-output",
        default=os.path.join("ml", "models", "model_metadata.json"),
    )
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Model Training (Isolation Forest)")
    print("=" * 60)
    print(f"  Input:         {args.input}")
    print(f"  Model output:  {args.model_output}")
    print(f"  Contamination: {args.contamination}")
    print(f"  N estimators:  {args.n_estimators}")
    print(f"  Random state:  {args.random_state}")
    print()

    # Load
    if not os.path.isfile(args.input):
        print(f"ERROR: Training data not found: {args.input}")
        sys.exit(1)

    df = pd.read_csv(args.input)

    # Determine features (must match ENABLED_FEATURES)
    features = [f for f in ENABLED_FEATURES if f in df.columns]
    if not features:
        print("ERROR: No enabled features found in the input data.")
        print(f"  ENABLED_FEATURES: {ENABLED_FEATURES}")
        print(f"  Input columns: {list(df.columns)}")
        sys.exit(1)

    print(f"  Features ({len(features)}): {features}")

    # Extract feature matrix — labels are NOT included
    X = df[features].values
    print(f"  Training samples: {X.shape[0]}")
    print(f"  Feature count:    {X.shape[1]}")

    # Assertion: 'label' must never be in the feature matrix
    assert "label" not in features, (
        "CRITICAL: 'label' is in the feature list. The model would be "
        "using the answer as an input."
    )

    # Report labels if present (informational only)
    has_labels = "label" in df.columns
    if has_labels:
        label_counts = df["label"].value_counts().to_dict()
        print(f"  Labels present (informational): {label_counts}")
        print("  NOTE: Labels are NOT used for Isolation Forest training.")
    print()

    # Validate data quality
    nan_count = int(np.isnan(X).sum())
    if nan_count > 0:
        print(f"  WARNING: {nan_count} NaN values in training data.")

    # Train
    print("  Training Isolation Forest...")
    start_time = time.time()
    model = train_isolation_forest(
        X,
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
    )
    train_duration = time.time() - start_time
    print(f"  Completed in {train_duration:.3f}s")

    # Training-set diagnostics (informational)
    predictions = model.predict(X)
    scores = model.decision_function(X)
    n_normal = int(np.sum(predictions == 1))
    n_anomaly = int(np.sum(predictions == -1))
    print()
    print("  Training set diagnostics (NOT test performance):")
    print(f"    Predicted normal:    {n_normal}")
    print(f"    Predicted anomalous: {n_anomaly}")
    print(f"    Score range: [{scores.min():.4f}, {scores.max():.4f}]")

    if has_labels:
        labels = df["label"].values
        pred_anomaly = predictions == -1
        label_anomaly = labels == 1
        tp = int(np.sum(pred_anomaly & label_anomaly))
        fp = int(np.sum(pred_anomaly & ~label_anomaly))
        tn = int(np.sum(~pred_anomaly & ~label_anomaly))
        fn = int(np.sum(~pred_anomaly & label_anomaly))
        print(f"    vs labels: TP={tp} FP={fp} TN={tn} FN={fn}")
        print("    (Training-set agreement. NOT generalisation performance.)")
    print()

    # Save model
    os.makedirs(os.path.dirname(args.model_output) or ".", exist_ok=True)
    joblib.dump(model, args.model_output)
    print(f"  Saved model to: {args.model_output}")

    # Save metadata
    metadata = {
        "project": "ARPShield",
        "model_type": "IsolationForest",
        "model_path": args.model_output,
        "scaler_path": os.path.join("ml", "models", "scaler.joblib"),
        "features": features,
        "feature_count": len(features),
        "contamination": args.contamination,
        "n_estimators": args.n_estimators,
        "random_state": args.random_state,
        "training_samples": int(X.shape[0]),
        "training_duration_seconds": round(train_duration, 3),
        "has_labels_in_training_data": has_labels,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "Isolation Forest is UNSUPERVISED. Labels (if present) were "
            "NOT used during model fitting. They appear only in "
            "training-set diagnostics."
        ),
    }

    os.makedirs(os.path.dirname(args.metadata_output) or ".", exist_ok=True)
    with open(args.metadata_output, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Saved metadata to: {args.metadata_output}")
    print()


if __name__ == "__main__":
    main()
