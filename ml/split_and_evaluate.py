"""
ARPShield — Strict ML Evaluation Pipeline
============================================
Implements a rigorous, leakage-free train/test methodology:

    RAW DATA
       ↓
    TRAIN / TEST SPLIT (stratified, before any feature engineering)
       ↓
    FIT FeatureEngineer ON TRAIN ONLY
       ↓
    TRANSFORM TRAIN → TRANSFORM TEST
       ↓
    FIT StandardScaler ON TRAIN ONLY
       ↓
    TRANSFORM TRAIN → TRANSFORM TEST
       ↓
    TRAIN Isolation Forest ON TRAIN ONLY
       ↓
    EVALUATE ON UNSEEN TEST SET

Also includes a reusable Feature Ablation Framework.

Usage:
    python ml/split_and_evaluate.py [--input PATH] [--test-size FLOAT]
                                    [--random-state INT] [--ablation]
"""

import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(__file__))
try:
    from feature_engineering import (
        ENABLED_FEATURES,
        FEATURE_REGISTRY,
        FeatureEngineer,
        load_raw_data,
    )
except ImportError:
    print("ERROR: Could not import feature_engineering.py")
    sys.exit(1)


# ===================================================================
# EVALUATION UTILITIES
# ===================================================================


def compute_metrics(y_true, y_pred_if):
    """
    Compute classification metrics.

    Parameters
    ----------
    y_true : array-like
        True labels (0=normal, 1=attack).
    y_pred_if : array-like
        Isolation Forest predictions (1=inlier, -1=outlier).

    Returns
    -------
    dict
        Metrics dictionary.
    """
    y_pred = (np.asarray(y_pred_if) == -1).astype(int)

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    acc = (tp + tn) / max(tp + tn + fp + fn, 1)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / max(fp + tn, 1)

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)
        },
    }


def print_metrics(metrics: dict, title: str):
    """Pretty-print a metrics dictionary."""
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")
    print(f"  Accuracy:            {metrics['accuracy']:.4f}")
    print(f"  Precision:           {metrics['precision']:.4f}")
    print(f"  Recall:              {metrics['recall']:.4f}")
    print(f"  F1-score:            {metrics['f1_score']:.4f}")
    print(f"  False Positive Rate: {metrics['false_positive_rate']:.4f}")
    cm = metrics["confusion_matrix"]
    print(f"\n  Confusion Matrix:")
    print(f"    TN: {cm['tn']:4d}   FP: {cm['fp']:4d}")
    print(f"    FN: {cm['fn']:4d}   TP: {cm['tp']:4d}")
    print()


# ===================================================================
# FEATURE ABLATION FRAMEWORK
# ===================================================================

# Predefined ablation experiments.
# Each experiment defines which features to use.
# New experiments can be added here without modifying the runner.

ABLATION_EXPERIMENTS = {
    "baseline": {
        "description": "All enabled features",
        "features": None,  # None means use all ENABLED_FEATURES
    },
    "drop_macs_per_ip": {
        "description": "Remove macs_per_ip",
        "features": [f for f in ENABLED_FEATURES if f != "macs_per_ip"],
    },
    "drop_timing": {
        "description": "Remove timing features (second)",
        "features": [f for f in ENABLED_FEATURES if f != "second"],
    },
    "drop_suspicious_format": {
        "description": "Remove suspicious packet-format features "
                       "(is_reply_with_zero_target, is_broadcast_target, "
                       "is_unspecified_sender)",
        "features": [
            f for f in ENABLED_FEATURES
            if f not in {
                "is_reply_with_zero_target",
                "is_broadcast_target",
                "is_unspecified_sender",
            }
        ],
    },
    "core_arp_only": {
        "description": "Only core ARP-behaviour features "
                       "(operation_encoded, macs_per_ip, sender_ip_frequency)",
        "features": [
            f for f in ENABLED_FEATURES
            if f in {"operation_encoded", "macs_per_ip", "sender_ip_frequency"}
        ],
    },
}

# Single-feature drop experiments (auto-generated)
for _feat in ENABLED_FEATURES:
    _key = f"drop_{_feat}"
    if _key not in ABLATION_EXPERIMENTS:
        ABLATION_EXPERIMENTS[_key] = {
            "description": f"Remove {_feat}",
            "features": [f for f in ENABLED_FEATURES if f != _feat],
        }


def run_ablation_experiment(
    train_raw: pd.DataFrame,
    test_raw: pd.DataFrame,
    features: list[str],
    contamination: float,
    random_state: int = 42,
) -> float:
    """
    Run one ablation experiment: engineer features, scale, train, evaluate.

    Parameters
    ----------
    train_raw, test_raw : pd.DataFrame
        Raw train/test data.
    features : list[str]
        Feature subset to use.
    contamination : float
        IF contamination parameter.
    random_state : int
        Random seed.

    Returns
    -------
    float
        Test F1-score.
    """
    engineer = FeatureEngineer(features=features)
    train_feat = engineer.fit_transform(train_raw)
    test_feat = engineer.transform(test_raw)

    X_tr = train_feat[features].values
    X_te = test_feat[features].values

    scaler = StandardScaler().fit(X_tr)
    X_tr_sc = scaler.transform(X_tr)
    X_te_sc = scaler.transform(X_te)

    model = IsolationForest(
        contamination=contamination,
        n_estimators=100,
        random_state=random_state,
    )
    model.fit(X_tr_sc)

    y_pred = (model.predict(X_te_sc) == -1).astype(int)
    return float(f1_score(test_feat["label"], y_pred, zero_division=0))


def run_ablation_study(
    train_raw: pd.DataFrame,
    test_raw: pd.DataFrame,
    contamination: float,
    random_state: int = 42,
    experiments: dict = None,
) -> dict:
    """
    Run all ablation experiments and return results.

    Parameters
    ----------
    train_raw, test_raw : pd.DataFrame
        Raw data partitions.
    contamination : float
        IF contamination.
    random_state : int
        Seed.
    experiments : dict, optional
        Override experiment definitions.

    Returns
    -------
    dict
        {experiment_name: {"description": ..., "f1": ..., "delta": ...}}
    """
    if experiments is None:
        experiments = ABLATION_EXPERIMENTS

    print("\n" + "=" * 60)
    print("  Feature Ablation Analysis")
    print("=" * 60)
    print(f"  {'Experiment':<35} | {'F1':>7} | {'Delta':>8}")
    print("  " + "-" * 55)

    results = {}
    baseline_f1 = None

    for name, config in experiments.items():
        features = config["features"]
        if features is None:
            features = ENABLED_FEATURES

        if not features:
            print(f"  {name:<35} | SKIP (no features)")
            continue

        f1 = run_ablation_experiment(
            train_raw, test_raw, features, contamination, random_state
        )

        if name == "baseline":
            baseline_f1 = f1
            delta_str = "  -"
        else:
            delta = f1 - (baseline_f1 or 0)
            delta_str = f"{delta:+.4f}"

        print(f"  {name:<35} | {f1:.4f} | {delta_str}")

        results[name] = {
            "description": config["description"],
            "features": features,
            "f1_score": round(f1, 4),
            "delta_from_baseline": round(f1 - (baseline_f1 or 0), 4) if baseline_f1 is not None and name != "baseline" else None,
        }

    return results


# ===================================================================
# MAIN PIPELINE
# ===================================================================


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Strict ML Evaluation Pipeline"
    )
    parser.add_argument(
        "--input",
        default=os.path.join("network", "final_arp_dataset.csv"),
    )
    parser.add_argument("--test-size", type=float, default=0.20)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--contamination", type=float, default=None,
                        help="IF contamination. Default: auto from train labels.")
    parser.add_argument("--ablation", action="store_true",
                        help="Run feature ablation study.")
    parser.add_argument(
        "--output-dir",
        default=os.path.join("ml", "data", "processed"),
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Strict ML Evaluation Pipeline")
    print("=" * 60)
    print(f"  Input:        {args.input}")
    print(f"  Test size:    {args.test_size}")
    print(f"  Random state: {args.random_state}")
    print()

    # ── Step 1: Load raw data ──
    raw_df = load_raw_data(args.input)
    print(f"  Loaded {len(raw_df)} packets")

    if "label" not in raw_df.columns:
        print("ERROR: This pipeline requires labelled data for evaluation.")
        sys.exit(1)

    label_counts = raw_df["label"].value_counts().to_dict()
    print(f"  Labels: {label_counts}")

    # ── Step 2: Train/Test split BEFORE any feature engineering ──
    print(f"\n  Splitting data (stratified, test_size={args.test_size})...")
    train_raw, test_raw = train_test_split(
        raw_df,
        test_size=args.test_size,
        random_state=args.random_state,
        stratify=raw_df["label"],
    )

    print(f"  Train: {len(train_raw)} (attack: {(train_raw['label']==1).sum()})")
    print(f"  Test:  {len(test_raw)} (attack: {(test_raw['label']==1).sum()})")

    # Assertion: no overlap
    assert len(set(train_raw.index) & set(test_raw.index)) == 0, (
        "LEAKAGE: Train and test indices overlap!"
    )

    # ── Step 3: Feature engineering (fit on train ONLY) ──
    print("\n  Feature engineering (fit on train, transform both)...")
    engineer = FeatureEngineer()
    train_feat = engineer.fit_transform(train_raw)
    test_feat = engineer.transform(test_raw)

    features = engineer.get_feature_names()
    print(f"  Features ({len(features)}): {features}")

    # Assertion: label is not a feature
    assert "label" not in features

    # ── Step 4: Scaling (fit on train ONLY) ──
    print("  Scaling (fit on train, transform both)...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_feat[features].values)
    y_train = train_feat["label"].values

    X_test = scaler.transform(test_feat[features].values)
    y_test = test_feat["label"].values

    # ── Step 5: Train model (on train ONLY) ──
    contamination = args.contamination
    if contamination is None:
        contamination = (y_train == 1).sum() / len(y_train)
    print(f"\n  Training IsolationForest (contamination={contamination:.4f})...")

    model = IsolationForest(
        contamination=contamination,
        n_estimators=100,
        random_state=args.random_state,
    )
    model.fit(X_train)

    # ── Step 6: Evaluate ──
    train_pred = model.predict(X_train)
    train_metrics = compute_metrics(y_train, train_pred)
    print_metrics(train_metrics, "TRAIN Set Results (informational only)")

    test_pred = model.predict(X_test)
    test_metrics = compute_metrics(y_test, test_pred)
    print_metrics(test_metrics, "TEST Set Results (held-out, unseen)")

    # ── Step 7: Ablation (optional) ──
    ablation_results = None
    if args.ablation:
        ablation_results = run_ablation_study(
            train_raw, test_raw, contamination, args.random_state
        )

    # ── Save results ──
    os.makedirs(args.output_dir, exist_ok=True)

    results = {
        "pipeline": "split_and_evaluate",
        "test_size": args.test_size,
        "random_state": args.random_state,
        "contamination": contamination,
        "features": features,
        "train_size": len(train_raw),
        "test_size_actual": len(test_raw),
        "train_metrics": train_metrics,
        "test_metrics": test_metrics,
        "note": (
            "Train metrics are informational only. Test metrics are the "
            "valid evaluation on unseen data. The model (Isolation Forest) "
            "is unsupervised — labels were not used during training."
        ),
    }
    if ablation_results:
        results["ablation"] = ablation_results

    results_path = os.path.join(args.output_dir, "evaluation_results.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Saved evaluation results to: {results_path}")

    # Save model artifacts for predict.py
    models_dir = os.path.join("ml", "models")
    os.makedirs(models_dir, exist_ok=True)

    joblib.dump(model, os.path.join(models_dir, "isolation_forest.joblib"))
    joblib.dump(scaler, os.path.join(models_dir, "scaler.joblib"))
    joblib.dump(engineer, os.path.join(models_dir, "feature_engineer.joblib"))

    from datetime import datetime, timezone
    metadata = {
        "project": "ARPShield",
        "model_type": "IsolationForest",
        "model_path": os.path.join(models_dir, "isolation_forest.joblib"),
        "scaler_path": os.path.join(models_dir, "scaler.joblib"),
        "features": features,
        "feature_count": len(features),
        "contamination": contamination,
        "n_estimators": 100,
        "random_state": args.random_state,
        "training_samples": int(len(train_raw)),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "note": "Trained via split_and_evaluate.py with strict leakage prevention.",
    }
    with open(os.path.join(models_dir, "model_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Saved model artifacts to: {models_dir}/")
    print()


if __name__ == "__main__":
    main()
