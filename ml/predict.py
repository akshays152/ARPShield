"""
ARPShield — Prediction Module
================================
Loads a trained Isolation Forest model and produces anomaly predictions
on new preprocessed ARP feature data.

Output:
    For each input sample, produces:
    - anomaly_prediction: 1 (normal) or -1 (anomalous)
    - anomaly_score: continuous score from decision_function
      (lower/more negative = more anomalous)
    - is_anomaly: boolean flag (True if prediction == -1)

The output is structured for consumption by the backend/risk engine.

Usage:
    python ml/predict.py [--input PATH] [--model PATH] [--scaler PATH]
                         [--feature-config PATH] [--output PATH]
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
    feature_config_path: str,
) -> tuple:
    """
    Load trained model, scaler, and feature configuration.

    Parameters
    ----------
    model_path : str
        Path to the trained model (joblib).
    scaler_path : str
        Path to the fitted scaler (joblib).
    feature_config_path : str
        Path to the feature configuration (JSON).

    Returns
    -------
    tuple
        (model, scaler, feature_config)
    """
    # Load model
    if not os.path.isfile(model_path):
        print(f"ERROR: Model file not found: {model_path}")
        sys.exit(1)
    model = joblib.load(model_path)

    # Load scaler
    if not os.path.isfile(scaler_path):
        print(f"ERROR: Scaler file not found: {scaler_path}")
        sys.exit(1)
    scaler = joblib.load(scaler_path)

    # Load feature config
    if not os.path.isfile(feature_config_path):
        print(f"ERROR: Feature config not found: {feature_config_path}")
        sys.exit(1)
    with open(feature_config_path, "r", encoding="utf-8") as f:
        feature_config = json.load(f)

    return model, scaler, feature_config


def predict(
    model,
    scaler,
    feature_config: dict,
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
        Fitted scaler.
    feature_config : dict
        Feature configuration (defines feature order).
    input_df : pd.DataFrame
        Input features. Must contain all model features.
    already_scaled : bool
        If True, skip scaling (data already preprocessed).

    Returns
    -------
    pd.DataFrame
        Input data augmented with prediction columns:
        - anomaly_prediction: 1 (normal) or -1 (anomalous)
        - anomaly_score: continuous anomaly score
        - is_anomaly: boolean anomaly flag
    """
    model_features = feature_config["model_features"]

    # Validate features
    missing = set(model_features) - set(input_df.columns)
    if missing:
        raise ValueError(
            f"Missing features in input data: {missing}. "
            f"Expected features: {model_features}"
        )

    # Extract features in exact training order
    X = input_df[model_features].values

    # Scale if not already scaled
    if not already_scaled:
        X = scaler.transform(X)

    # Predict
    predictions = model.predict(X)
    scores = model.decision_function(X)

    # Build output DataFrame
    result_df = input_df.copy()
    result_df["anomaly_prediction"] = predictions
    result_df["anomaly_score"] = np.round(scores, 6)
    result_df["is_anomaly"] = predictions == -1

    return result_df


def format_output_json(result_df: pd.DataFrame, feature_config: dict) -> list[dict]:
    """
    Format prediction results as structured JSON for backend consumption.

    Parameters
    ----------
    result_df : pd.DataFrame
        DataFrame with prediction results.
    feature_config : dict
        Feature configuration metadata.

    Returns
    -------
    list[dict]
        List of prediction records.
    """
    records = []
    for _, row in result_df.iterrows():
        record = {
            "window_start": float(row.get("window_start", 0)),
            "anomaly_prediction": int(row["anomaly_prediction"]),
            "anomaly_score": float(row["anomaly_score"]),
            "is_anomaly": bool(row["is_anomaly"]),
            "model_type": feature_config.get("model_type", "IsolationForest"),
            "features": {
                feat: float(row[feat])
                for feat in feature_config["model_features"]
                if feat in row.index
            },
        }
        records.append(record)
    return records


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Predict anomalies using trained model"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("ml", "data", "processed", "features.csv"),
        help="Path to feature data CSV (unscaled; scaler will be applied)",
    )
    parser.add_argument(
        "--model",
        default=os.path.join("ml", "models", "isolation_forest.joblib"),
        help="Path to trained model (default: ml/models/isolation_forest.joblib)",
    )
    parser.add_argument(
        "--scaler",
        default=os.path.join("ml", "models", "scaler.joblib"),
        help="Path to fitted scaler (default: ml/models/scaler.joblib)",
    )
    parser.add_argument(
        "--feature-config",
        default=os.path.join("ml", "models", "feature_config.json"),
        help="Path to feature config JSON (default: ml/models/feature_config.json)",
    )
    parser.add_argument(
        "--output",
        default=os.path.join("ml", "data", "processed", "predictions.csv"),
        help="Output path for predictions CSV (default: ml/data/processed/predictions.csv)",
    )
    parser.add_argument(
        "--json-output",
        default=os.path.join("ml", "data", "processed", "predictions.json"),
        help="Output path for predictions JSON (default: ml/data/processed/predictions.json)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Anomaly Prediction")
    print("=" * 60)
    print(f"  Input:          {args.input}")
    print(f"  Model:          {args.model}")
    print(f"  Scaler:         {args.scaler}")
    print(f"  Feature config: {args.feature_config}")
    print()

    # Load artifacts
    print("  Loading model artifacts...")
    model, scaler, feature_config = load_model_artifacts(
        args.model, args.scaler, args.feature_config
    )
    print(f"  Model type:     {feature_config.get('model_type', 'Unknown')}")
    print(f"  Feature count:  {feature_config.get('feature_count', 'Unknown')}")
    print()

    # Load input data
    print("  Loading input features...")
    input_df = pd.read_csv(args.input)
    print(f"  Input samples:  {len(input_df)}")
    print()

    # Generate predictions
    print("  Generating predictions...")
    result_df = predict(
        model, scaler, feature_config, input_df, already_scaled=False
    )

    # Summary
    n_normal = int((result_df["anomaly_prediction"] == 1).sum())
    n_anomaly = int((result_df["anomaly_prediction"] == -1).sum())
    print()
    print("  Prediction summary:")
    print(f"    Total samples:      {len(result_df)}")
    print(f"    Normal:             {n_normal} ({100 * n_normal / len(result_df):.1f}%)")
    print(f"    Anomalous:          {n_anomaly} ({100 * n_anomaly / len(result_df):.1f}%)")
    print(f"    Score range:        [{result_df['anomaly_score'].min():.4f}, {result_df['anomaly_score'].max():.4f}]")
    print()

    # Show anomalous samples
    if n_anomaly > 0:
        print("  Anomalous windows detected:")
        anomalies = result_df[result_df["is_anomaly"]]
        for _, row in anomalies.head(10).iterrows():
            ws = row.get("window_start", "N/A")
            score = row["anomaly_score"]
            print(f"    window_start={ws}  score={score:.4f}")
        if n_anomaly > 10:
            print(f"    ... and {n_anomaly - 10} more")
    print()

    # Save CSV output
    os.makedirs(os.path.dirname(args.output) if os.path.dirname(args.output) else ".", exist_ok=True)
    result_df.to_csv(args.output, index=False)
    print(f"  Saved predictions CSV to: {args.output}")

    # Save JSON output (for backend/risk engine consumption)
    json_records = format_output_json(result_df, feature_config)
    with open(args.json_output, "w", encoding="utf-8") as f:
        json.dump(json_records, f, indent=2)
    print(f"  Saved predictions JSON to: {args.json_output}")
    print()


if __name__ == "__main__":
    main()
