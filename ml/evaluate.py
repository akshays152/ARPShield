"""
ARPShield — Evaluation Module
================================
Evaluates the trained anomaly detection model's predictions.

IMPORTANT DISTINCTION:
    Isolation Forest is an UNSUPERVISED model — it does not use labels
    during training. Labels (if available) are used ONLY for post-hoc
    evaluation of how well the model's anomaly predictions align with
    known ground truth.

This module supports two modes:
    1. SUPERVISED evaluation (labels available):
       Computes Accuracy, Precision, Recall, F1-score, FPR,
       Confusion Matrix, and score distributions by true label.

    2. UNSUPERVISED evaluation (no labels):
       Computes score distribution statistics and prediction counts.

Label mapping:
    Person 1's labels:     0 = normal,  1 = attack
    Isolation Forest:      1 = inlier, -1 = outlier/anomaly
    For evaluation:        label==1 <-> prediction==-1

Usage:
    python ml/evaluate.py [--predictions PATH] [--output-dir PATH]
                          [--dataset-name NAME]
"""

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


def evaluate_unsupervised(df: pd.DataFrame, output_dir: str) -> dict:
    """Evaluate without ground-truth labels."""
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
        },
        "note": (
            "Unsupervised evaluation — no ground-truth labels. "
            "These statistics describe model behaviour, not accuracy."
        ),
    }

    return metrics


def evaluate_supervised(
    df: pd.DataFrame,
    output_dir: str,
    dataset_name: str = "Test",
) -> dict:
    """
    Evaluate with ground-truth labels.

    Parameters
    ----------
    df : pd.DataFrame
        Must contain 'anomaly_prediction', 'anomaly_score', 'label'.
    output_dir : str
        Directory for output files.
    dataset_name : str
        Name to use in output (e.g. "Train", "Test").

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

    # Map: label==1 (attack) <-> prediction==-1 (anomaly)
    y_true = (df["label"] == 1).astype(int).values
    y_pred = (df["anomaly_prediction"] == -1).astype(int).values
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
        "dataset_name": dataset_name,
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
        "note": (
            "Isolation Forest is UNSUPERVISED. Labels were NOT used during "
            "training. This evaluation measures how well the model's "
            "unsupervised anomaly judgments align with known labels."
        ),
    }

    # Score distributions by true label
    normal_scores = scores[y_true == 0]
    attack_scores = scores[y_true == 1]
    if len(normal_scores) > 0 and len(attack_scores) > 0:
        metrics["score_by_true_label"] = {
            "normal_mean": round(float(np.mean(normal_scores)), 6),
            "attack_mean": round(float(np.mean(attack_scores)), 6),
        }

    # Plots
    if HAS_MATPLOTLIB and output_dir:
        # Confusion matrix
        fig, ax = plt.subplots(figsize=(7, 5))
        im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        ax.set_title(f"ARPShield — Confusion Matrix ({dataset_name})")
        ax.set_xlabel("Predicted")
        ax.set_ylabel("True")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Normal", "Attack"])
        ax.set_yticklabels(["Normal", "Attack"])
        for i in range(2):
            for j in range(2):
                ax.text(
                    j, i, str(cm[i, j]), ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black",
                    fontsize=16,
                )
        fig.colorbar(im)
        plot_path = os.path.join(output_dir, f"confusion_matrix_{dataset_name.lower()}.png")
        fig.savefig(plot_path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        # Score distribution
        fig, ax = plt.subplots(figsize=(10, 6))
        ax.hist(normal_scores, bins=50, alpha=0.7,
                label=f"Normal (n={len(normal_scores)})", color="#2196F3")
        ax.hist(attack_scores, bins=50, alpha=0.7,
                label=f"Attack (n={len(attack_scores)})", color="#F44336")
        ax.set_xlabel("Anomaly Score")
        ax.set_ylabel("Count")
        ax.set_title(f"ARPShield — Score Distribution ({dataset_name})")
        ax.legend()
        ax.grid(True, alpha=0.3)
        plot_path = os.path.join(output_dir, f"score_distribution_{dataset_name.lower()}.png")
        fig.savefig(plot_path, dpi=150, bbox_inches="tight")
        plt.close(fig)

    return metrics


def main():
    parser = argparse.ArgumentParser(
        description="ARPShield — Evaluate model predictions"
    )
    parser.add_argument(
        "--predictions",
        default=os.path.join("ml", "data", "processed", "predictions.csv"),
    )
    parser.add_argument(
        "--output-dir",
        default=os.path.join("ml", "data", "processed"),
    )
    parser.add_argument(
        "--dataset-name",
        default="Test",
        help="Name of the dataset being evaluated (e.g. Train, Test)",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("ARPShield — Model Evaluation")
    print("=" * 60)
    print(f"  Predictions: {args.predictions}")
    print(f"  Dataset:     {args.dataset_name}")
    print()

    if not os.path.isfile(args.predictions):
        print(f"ERROR: Predictions file not found: {args.predictions}")
        sys.exit(1)

    df = pd.read_csv(args.predictions)

    required = {"anomaly_prediction", "anomaly_score"}
    if not required.issubset(set(df.columns)):
        print(f"ERROR: Missing required columns: {required - set(df.columns)}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    if "label" in df.columns:
        print("  Labels found — SUPERVISED evaluation")
        print("  (Isolation Forest is unsupervised; labels are used for")
        print("   post-hoc evaluation only, not for training.)")
        print()
        metrics = evaluate_supervised(df, args.output_dir, args.dataset_name)

        print(f"  === {args.dataset_name} Set Results ===")
        print(f"    Accuracy:            {metrics['accuracy']:.4f}")
        print(f"    Precision:           {metrics['precision']:.4f}")
        print(f"    Recall:              {metrics['recall']:.4f}")
        print(f"    F1-score:            {metrics['f1_score']:.4f}")
        print(f"    False Positive Rate: {metrics['false_positive_rate']:.4f}")
        cm = metrics["confusion_matrix"]
        print(f"    Confusion Matrix: TN={cm['true_negative']} FP={cm['false_positive']} "
              f"FN={cm['false_negative']} TP={cm['true_positive']}")
    else:
        print("  No labels — UNSUPERVISED evaluation")
        metrics = evaluate_unsupervised(df, args.output_dir)

        stats = metrics["score_statistics"]
        print(f"  Normal:    {metrics['normal_count']}")
        print(f"  Anomalous: {metrics['anomaly_count']}")
        print(f"  Score mean={stats['mean']:.6f} std={stats['std']:.6f}")

    print()

    # Save metrics
    serialisable = {
        k: v for k, v in metrics.items()
        if isinstance(v, (str, int, float, dict, list, bool))
    }
    metrics_path = os.path.join(args.output_dir, "evaluation_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(serialisable, f, indent=2)
    print(f"  Saved metrics to: {metrics_path}")
    print()


if __name__ == "__main__":
    main()
