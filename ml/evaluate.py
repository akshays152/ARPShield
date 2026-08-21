"""
ARPShield — Evaluation Module
================================
Evaluates the trained anomaly detection model.

Since Person 1 has provided labelled data (0=normal, 1=attack), this
module can now run proper SUPERVISED evaluation with:
    - Precision, Recall, F1-score
    - Confusion matrix (TP, FP, TN, FN)
    - False positive rate (FPR)
    - Score distribution analysis

The module auto-detects whether labels are present and selects the
appropriate evaluation mode.

Note on label mapping:
    - Person 1's labels:     0 = normal,  1 = attack
    - Isolation Forest:      1 = inlier, -1 = outlier/anomaly
    - For evaluation we map: label 1 (attack) <-> prediction -1 (anomaly)

Usage:
    python ml/evaluate.py [--predictions PATH] [--output-dir PATH]
"""

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend for saving plots
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def evaluate_unsupervised(df: pd.DataFrame, output_dir: str) -> dict:
    """
    Evaluate model output without ground-truth labels.

    Produces distribution analysis and diagnostic statistics.

    Parameters
    ----------
    df : pd.DataFrame
        Prediction results with 'anomaly_score', 'anomaly_prediction'.
    output_dir : str
        Directory to save evaluation outputs.

    Returns
    -------
    dict
        Evaluation metrics and diagnostics.
    """
    scores = df["anomaly_score"].values
    predictions = df["anomaly_prediction"].values

    n_total = len(df)
    n_normal = int(np.sum(predictions == 1))
    n_anomaly = int(np.sum(predictions == -1))

    metrics = {
        "evaluation_mode": "unsupervised",
        "total_samples": n_total,
        "normal_count": n_normal,
        "anomaly_count": n_anomaly,
        "anomaly_rate": round(n_anomaly / max(n_total, 1), 4),
        "score_statistics": {
            "mean": round(float(np.mean(scores)), 6),
            "std": round(float(np.std(scores)), 6),
            "min": round(float(np.min(scores)), 6),
            "max": round(float(np.max(scores)), 6),
            "median": round(float(np.median(scores)), 6),
            "q25": round(float(np.percentile(scores, 25)), 6),
            "q75": round(float(np.percentile(scores, 75)), 6),
        },
        "note": (
            "Unsupervised evaluation — no ground-truth labels available. "
            "These statistics describe model behaviour, not detection accuracy."
        ),
    }

    if n_anomaly > 0:
        normal_scores = scores[predictions == 1]
        anomaly_scores = scores[predictions == -1]
        metrics["normal_score_stats"] = {
            "mean": round(float(np.mean(normal_scores)), 6),
            "std": round(float(np.std(normal_scores)), 6),
        }
        metrics["anomaly_score_stats"] = {
            "mean": round(float(np.mean(anomaly_scores)), 6),
            "std": round(float(np.std(anomaly_scores)), 6),
        }

    if HAS_MATPLOTLIB:
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.hist(scores[predictions == 1], bins=30, alpha=0.7,
                label="Normal", color="#2196F3")
        if n_anomaly > 0:
            ax.hist(scores[predictions == -1], bins=30, alpha=0.7,
                    label="Anomalous", color="#F44336")
        ax.set_xlabel("Anomaly Score (decision_function)")
        ax.set_ylabel("Count")
        ax.set_title("ARPShield — Anomaly Score Distribution")
        ax.legend()
        ax.grid(True, alpha=0.3)
        plot_path = os.path.join(output_dir, "score_distribution.png")
        fig.savefig(plot_path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        metrics["score_distribution_plot"] = plot_path

    return metrics


def evaluate_supervised(df: pd.DataFrame, output_dir: str) -> dict:
    """
    Evaluate model output using ground-truth labels from Person 1's data.

    Label mapping:
        Person 1: 0=normal, 1=attack
        IF model: 1=normal, -1=anomaly
        For sklearn: 1=positive (anomaly/attack), 0=negative (normal)

    Parameters
    ----------
    df : pd.DataFrame
        Prediction results with 'anomaly_prediction' and 'label' columns.
    output_dir : str
        Directory to save evaluation outputs.

    Returns
    -------
    dict
        Classification metrics.
    """
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
    )

    # Map to binary: 1 = anomaly/attack (positive class), 0 = normal
    y_true = (df["label"] == 1).astype(int).values       # Person 1: 1=attack
    y_pred = (df["anomaly_prediction"] == -1).astype(int).values  # IF: -1=anomaly

    scores = df["anomaly_score"].values

    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / max(fp + tn, 1)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)

    metrics = {
        "evaluation_mode": "supervised",
        "total_samples": len(df),
        "label_distribution": {
            "normal": int((y_true == 0).sum()),
            "attack": int((y_true == 1).sum()),
        },
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "classification_report": classification_report(
            y_true, y_pred,
            target_names=["Normal", "Attack/Anomaly"],
            zero_division=0,
        ),
    }

    # Score distributions by true label
    normal_scores = scores[y_true == 0]
    attack_scores = scores[y_true == 1]
    metrics["score_by_true_label"] = {
        "normal": {
            "mean": round(float(np.mean(normal_scores)), 6),
            "std": round(float(np.std(normal_scores)), 6),
            "min": round(float(np.min(normal_scores)), 6),
            "max": round(float(np.max(normal_scores)), 6),
        },
        "attack": {
            "mean": round(float(np.mean(attack_scores)), 6),
            "std": round(float(np.std(attack_scores)), 6),
            "min": round(float(np.min(attack_scores)), 6),
            "max": round(float(np.max(attack_scores)), 6),
        },
    }

    if HAS_MATPLOTLIB:
        # Confusion matrix heatmap
        fig, ax = plt.subplots(figsize=(8, 6))
        im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        ax.set_title("ARPShield — Confusion Matrix")
        ax.set_xlabel("Predicted Label")
        ax.set_ylabel("True Label")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Normal", "Attack"])
        ax.set_yticklabels(["Normal", "Attack"])
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black",
                        fontsize=16)
        fig.colorbar(im)
        plot_path = os.path.join(output_dir, "confusion_matrix.png")
        fig.savefig(plot_path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        metrics["confusion_matrix_plot"] = plot_path
        print(f"  Saved confusion matrix plot: {plot_path}")

        # Score distribution by true label
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.hist(normal_scores, bins=50, alpha=0.7,
                label=f"Normal (n={len(normal_scores)})", color="#2196F3")
        ax.hist(attack_scores, bins=50, alpha=0.7,
                label=f"Attack (n={len(attack_scores)})", color="#F44336")
        ax.set_xlabel("Anomaly Score (decision_function)")
        ax.set_ylabel("Count")
        ax.set_title("ARPShield — Score Distribution by True Label")
        ax.legend()
        ax.grid(True, alpha=0.3)
        plot_path = os.path.join(output_dir, "score_distribution_by_label.png")
        fig.savefig(plot_path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        metrics["score_distribution_plot"] = plot_path
        print(f"  Saved score distribution plot: {plot_path}")

    return metrics


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Evaluate anomaly detection model"
    )
    parser.add_argument(
        "--predictions",
        default=os.path.join("ml", "data", "processed", "predictions.csv"),
        help="Path to predictions CSV",
    )
    parser.add_argument(
        "--output-dir",
        default=os.path.join("ml", "data", "processed"),
        help="Directory for evaluation outputs",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Model Evaluation")
    print("=" * 60)
    print(f"  Predictions: {args.predictions}")
    print(f"  Output dir:  {args.output_dir}")
    print()

    if not os.path.isfile(args.predictions):
        print(f"ERROR: Predictions file not found: {args.predictions}")
        sys.exit(1)

    df = pd.read_csv(args.predictions)
    print(f"  Loaded {len(df)} prediction samples")

    required = {"anomaly_prediction", "anomaly_score"}
    if not required.issubset(set(df.columns)):
        print(f"ERROR: Missing required columns. Need: {required}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    # Select evaluation mode based on label presence
    if "label" in df.columns:
        print("  Ground-truth labels found — running SUPERVISED evaluation")
        print(f"  Label distribution: {dict(df['label'].value_counts())}")
        print()
        metrics = evaluate_supervised(df, args.output_dir)

        print("  === Classification Results ===")
        print(f"    Accuracy:           {metrics['accuracy']:.4f}")
        print(f"    Precision:          {metrics['precision']:.4f}")
        print(f"    Recall:             {metrics['recall']:.4f}")
        print(f"    F1-score:           {metrics['f1_score']:.4f}")
        print(f"    False Positive Rate: {metrics['false_positive_rate']:.4f}")
        print()
        print("  Confusion Matrix:")
        cm = metrics["confusion_matrix"]
        print(f"    TN={cm['true_negative']}  FP={cm['false_positive']}")
        print(f"    FN={cm['false_negative']}  TP={cm['true_positive']}")
        print()
        print("  Full Classification Report:")
        print(metrics["classification_report"])

        # Score separation
        sc = metrics["score_by_true_label"]
        print(f"  Score separation (normal vs attack):")
        print(f"    Normal mean:  {sc['normal']['mean']:.4f}")
        print(f"    Attack mean:  {sc['attack']['mean']:.4f}")
    else:
        print("  No ground-truth labels found — running UNSUPERVISED evaluation")
        print()
        metrics = evaluate_unsupervised(df, args.output_dir)

        stats = metrics["score_statistics"]
        print(f"  Score Distribution:")
        print(f"    Mean:   {stats['mean']:.6f}")
        print(f"    Std:    {stats['std']:.6f}")
        print(f"    Min:    {stats['min']:.6f}")
        print(f"    Max:    {stats['max']:.6f}")
        print()
        print(f"  Prediction Counts:")
        print(f"    Normal:    {metrics['normal_count']}")
        print(f"    Anomalous: {metrics['anomaly_count']}")

    print()

    # Save metrics
    serialisable_metrics = {
        k: v for k, v in metrics.items()
        if isinstance(v, (str, int, float, dict, list, bool))
    }
    metrics_path = os.path.join(args.output_dir, "evaluation_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(serialisable_metrics, f, indent=2)
    print(f"  Saved evaluation metrics to: {metrics_path}")
    print()


if __name__ == "__main__":
    main()
