"""
ARPShield — Prediction Module
================================
Loads a trained Isolation Forest model and its associated artifacts
(scaler, metadata) and produces anomaly predictions on new data.

This module guarantees:
    1. The exact trained model is loaded.
    2. The exact fitted scaler is loaded and applied.
    3. The exact feature order from training is enforced.
    4. Missing features are rejected with a clear error.
    5. Labels are NEVER used as model input.

Output format (per sample):
    {
        "prediction": "anomaly" or "normal",
        "anomaly_score": <float>,
        "is_anomaly": <bool>,
        "model_type": "IsolationForest"
    }

Usage:
    python ml/predict.py [--input PATH] [--model PATH] [--scaler PATH]
                         [--metadata PATH] [--output PATH]
"""

import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd


def load_model_artifacts(
    model_path: str,
    scaler_path: str,
    metadata_path: str,
) -> tuple:
    """
    Load trained model, scaler, and metadata.

    Parameters
    ----------
    model_path : str
        Path to trained model (joblib).
    scaler_path : str
        Path to fitted scaler (joblib).
    metadata_path : str
        Path to model metadata (JSON).

    Returns
    -------
    tuple
        (model, scaler, metadata_dict)

    Raises
    ------
    FileNotFoundError
        If any artifact is missing.
    """
    for path, name in [
        (model_path, "Model"),
        (scaler_path, "Scaler"),
        (metadata_path, "Metadata"),
    ]:
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{name} file not found: {path}")

    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)

    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    return model, scaler, metadata


def predict(
    model,
    scaler,
    metadata: dict,
    input_df: pd.DataFrame,
    already_scaled: bool = False,
) -> pd.DataFrame:
    """
    Generate anomaly predictions for input data.

    Parameters
    ----------
    model : IsolationForest
        Trained model.
    scaler : StandardScaler
        Fitted scaler (from training data).
    metadata : dict
        Model metadata (contains feature list and order).
    input_df : pd.DataFrame
        Input features. Must contain all features listed in metadata.
    already_scaled : bool
        If True, skip scaling (data already preprocessed).

    Returns
    -------
    pd.DataFrame
        Input data augmented with prediction columns.

    Raises
    ------
    ValueError
        If required features are missing from input data.
    """
    model_features = metadata["features"]

    # Validate all required features are present
    missing = set(model_features) - set(input_df.columns)
    if missing:
        raise ValueError(
            f"Missing required features in input data: {missing}. "
            f"Expected features (in order): {model_features}. "
            f"Found columns: {list(input_df.columns)}"
        )

    # Assertion: label must NOT be in the feature list
    assert "label" not in model_features, (
        "CRITICAL: 'label' is in the model feature list."
    )

    # Extract features in exact training order
    X = input_df[model_features].values

    # Scale if needed
    if not already_scaled:
        assert X.shape[1] == len(scaler.mean_), (
            f"Feature count mismatch: input has {X.shape[1]} features "
            f"but scaler expects {len(scaler.mean_)}."
        )
        X = scaler.transform(X)

    # Predict
    raw_predictions = model.predict(X)
    scores = model.decision_function(X)

    # Build output
    result_df = input_df.copy()
    result_df["anomaly_prediction"] = raw_predictions
    result_df["anomaly_score"] = np.round(scores, 6)
    result_df["is_anomaly"] = raw_predictions == -1

    return result_df


def format_output_json(
    result_df: pd.DataFrame, metadata: dict
) -> list[dict]:
    """
    Format prediction results as structured JSON for Person 4's risk
    engine and Person 5's backend.

    Parameters
    ----------
    result_df : pd.DataFrame
        DataFrame with prediction columns.
    metadata : dict
        Model metadata.

    Returns
    -------
    list[dict]
        List of prediction records.
    """
    records = []
    for _, row in result_df.iterrows():
        record = {
            "prediction": "anomaly" if row["is_anomaly"] else "normal",
            "anomaly_score": float(row["anomaly_score"]),
            "is_anomaly": bool(row["is_anomaly"]),
            "model_type": metadata.get("model_type", "IsolationForest"),
        }
        records.append(record)
    return records


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Predict anomalies"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("ml", "data", "processed", "features.csv"),
        help="Feature data CSV (unscaled)",
    )
    parser.add_argument(
        "--model",
        default=os.path.join("ml", "models", "isolation_forest.joblib"),
    )
    parser.add_argument(
        "--scaler",
        default=os.path.join("ml", "models", "scaler.joblib"),
    )
    parser.add_argument(
        "--metadata",
        default=os.path.join("ml", "models", "model_metadata.json"),
    )
    parser.add_argument(
        "--output",
        default=os.path.join("ml", "data", "processed", "predictions.csv"),
    )
    parser.add_argument(
        "--json-output",
        default=os.path.join("ml", "data", "processed", "predictions.json"),
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Anomaly Prediction")
    print("=" * 60)
    print(f"  Input:    {args.input}")
    print(f"  Model:    {args.model}")
    print(f"  Scaler:   {args.scaler}")
    print(f"  Metadata: {args.metadata}")
    print()

    # Load artifacts
    print("  Loading model artifacts...")
    model, scaler, metadata = load_model_artifacts(
        args.model, args.scaler, args.metadata
    )
    print(f"  Model type:    {metadata.get('model_type', 'Unknown')}")
    print(f"  Features ({metadata.get('feature_count', '?')}): "
          f"{metadata.get('features', [])}")
    print()

    # Load input
    if not os.path.isfile(args.input):
        print(f"ERROR: Input file not found: {args.input}")
        sys.exit(1)

    input_df = pd.read_csv(args.input)
    print(f"  Input samples: {len(input_df)}")
    print()

    # Predict
    print("  Generating predictions...")
    result_df = predict(model, scaler, metadata, input_df, already_scaled=False)

    n_normal = int((result_df["anomaly_prediction"] == 1).sum())
    n_anomaly = int((result_df["anomaly_prediction"] == -1).sum())
    print(f"  Normal:    {n_normal}")
    print(f"  Anomalous: {n_anomaly}")
    print(f"  Score range: [{result_df['anomaly_score'].min():.4f}, "
          f"{result_df['anomaly_score'].max():.4f}]")
    print()

    # Save
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    result_df.to_csv(args.output, index=False)
    print(f"  Saved predictions CSV: {args.output}")

    json_records = format_output_json(result_df, metadata)
    with open(args.json_output, "w", encoding="utf-8") as f:
        json.dump(json_records, f, indent=2)
    print(f"  Saved predictions JSON: {args.json_output}")
    print()


if __name__ == "__main__":
    main()
