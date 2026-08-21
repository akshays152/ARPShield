"""
ARPShield — Strict ML Evaluation Methodology
==============================================
This script implements a rigorous train/test methodology to avoid data leakage
and calculate true generalization metrics for the ARP anomaly detection model.

Methodology:
    1. Loads raw dataset.
    2. Performs Stratified Random Split (80% train, 20% test).
       Note: Time-based split is not possible because all 6,000 packets were
       captured in the same 24-second window.
    3. Fits FeatureEngineer on train data, transforms both train and test.
       (Prevents `macs_per_ip` leakage)
    4. Fits StandardScaler on train data, transforms both train and test.
    5. Trains IsolationForest on train data.
    6. Evaluates model strictly on the held-out test data.
    7. Runs feature ablation to detect dataset shortcuts.
"""

import argparse
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

# Import custom FeatureEngineer
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
try:
    from feature_engineering import FeatureEngineer, PER_PACKET_FEATURES, load_raw_data
except ImportError:
    print("ERROR: Could not import feature_engineering.py")
    sys.exit(1)


def evaluate_predictions(y_true, y_pred_if, scores, dataset_name="Test"):
    """Evaluate model predictions."""
    # IF returns 1 for inlier, -1 for outlier. We map -1 to 1 (attack)
    y_pred = (y_pred_if == -1).astype(int)
    
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / max(fp + tn, 1)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)

    print(f"\n=== {dataset_name} Set Results ===")
    print(f"Accuracy:            {accuracy:.4f}")
    print(f"Precision:           {precision:.4f}")
    print(f"Recall:              {recall:.4f}")
    print(f"F1-score:            {f1:.4f}")
    print(f"False Positive Rate: {fpr:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"  TN: {tn:4d}   FP: {fp:4d}")
    print(f"  FN: {fn:4d}   TP: {tp:4d}")
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=["Normal", "Attack"]))
    
    return accuracy, precision, recall, f1, fpr


def run_ablation_study(df_train, df_test, contamination, features_to_test):
    """Retrain model omitting one feature at a time to determine importance/shortcuts."""
    print("\n=== Feature Ablation Analysis ===")
    print("Removing one feature at a time to see impact on Test F1-Score.")
    print(f"{'Omitted Feature':<30} | {'Test F1':<10} | {'Delta':<10}")
    print("-" * 55)
    
    # Baseline F1
    X_tr_base = df_train[features_to_test].values
    X_te_base = df_test[features_to_test].values
    
    scaler = StandardScaler().fit(X_tr_base)
    X_tr_sc = scaler.transform(X_tr_base)
    X_te_sc = scaler.transform(X_te_base)
    
    model = IsolationForest(contamination=contamination, n_estimators=100, random_state=42)
    model.fit(X_tr_sc)
    
    y_pred = (model.predict(X_te_sc) == -1).astype(int)
    baseline_f1 = f1_score(df_test["label"], y_pred, zero_division=0)
    
    print(f"{'BASELINE (All Features)':<30} | {baseline_f1:.4f}     | -")
    
    for feat in features_to_test:
        ablated_features = [f for f in features_to_test if f != feat]
        
        X_tr = df_train[ablated_features].values
        X_te = df_test[ablated_features].values
        
        sc = StandardScaler().fit(X_tr)
        X_tr_sc = sc.transform(X_tr)
        X_te_sc = sc.transform(X_te)
        
        m = IsolationForest(contamination=contamination, n_estimators=100, random_state=42)
        m.fit(X_tr_sc)
        
        pred = (m.predict(X_te_sc) == -1).astype(int)
        f1 = f1_score(df_test["label"], pred, zero_division=0)
        delta = f1 - baseline_f1
        
        print(f"{feat:<30} | {f1:.4f}     | {delta:+.4f}")


def main():
    print("=" * 60)
    print("ARPShield — Strict ML Evaluation Methodology")
    print("=" * 60)

    # 1. Load Data
    raw_path = os.path.join("network", "final_arp_dataset.csv")
    print(f"Loading raw dataset: {raw_path}")
    raw_df = load_raw_data(raw_path)
    print(f"Total samples: {len(raw_df)}")
    
    if "label" not in raw_df.columns:
        print("ERROR: Dataset must have 'label' column for evaluation.")
        sys.exit(1)

    # 2. Train/Test Split
    print("\nPerforming Stratified Random Split (80% Train, 20% Test)")
    # Note: Using random split because time window is only 24 seconds.
    train_raw, test_raw = train_test_split(
        raw_df, test_size=0.20, random_state=42, stratify=raw_df["label"]
    )
    
    print(f"  Train set size: {len(train_raw)} (Attacks: {(train_raw['label']==1).sum()})")
    print(f"  Test set size:  {len(test_raw)} (Attacks: {(test_raw['label']==1).sum()})")

    # 3. Feature Engineering (Strict Separation)
    print("\nEngineering features (Strict Fit on Train, Transform on Both)")
    engineer = FeatureEngineer()
    
    train_feat = engineer.fit_transform(train_raw)
    test_feat = engineer.transform(test_raw)
    
    features = PER_PACKET_FEATURES
    print(f"Using {len(features)} features: {features}")

    # 4. Scaling (Strict Separation)
    print("\nScaling features (Fit on Train, Transform on Both)")
    scaler = StandardScaler()
    
    X_train = scaler.fit_transform(train_feat[features].values)
    y_train = train_feat["label"].values
    
    X_test = scaler.transform(test_feat[features].values)
    y_test = test_feat["label"].values

    # 5. Train Model
    contamination = (y_train == 1).sum() / len(y_train)
    print(f"\nTraining IsolationForest on Train Set (Contamination={contamination:.4f})")
    model = IsolationForest(contamination=contamination, n_estimators=100, random_state=42)
    model.fit(X_train)

    # 6. Evaluation
    print("\nGenerating predictions on Test Set...")
    train_pred = model.predict(X_train)
    train_scores = model.decision_function(X_train)
    evaluate_predictions(y_train, train_pred, train_scores, "Train")

    test_pred = model.predict(X_test)
    test_scores = model.decision_function(X_test)
    evaluate_predictions(y_test, test_pred, test_scores, "Test (Held-Out)")
    
    # 7. Ablation Study
    run_ablation_study(train_feat, test_feat, contamination, features)

if __name__ == "__main__":
    main()
