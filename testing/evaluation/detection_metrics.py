"""
Detection Metrics — Cybersecurity evaluation for the rule-based detection engine.

Computes True Positives, True Negatives, False Positives, False Negatives,
Detection Rate, False Positive Rate, False Negative Rate, Precision,
Recall, and F1 Score.

These are standard cybersecurity detection-system evaluation metrics,
NOT machine-learning model metrics.
"""

from typing import Dict, Any, List


def compute_confusion_values(
    expected_detection: bool,
    actual_detected: bool,
) -> str:
    """Classify a single test-case outcome.

    Returns one of: 'TP', 'TN', 'FP', 'FN'.
    """
    if expected_detection and actual_detected:
        return "TP"
    if not expected_detection and not actual_detected:
        return "TN"
    if not expected_detection and actual_detected:
        return "FP"
    # expected_detection and not actual_detected
    return "FN"


def compute_detection_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute aggregate detection metrics from a list of scenario results.

    Each entry in *results* must contain at least:
        - expected_detection: bool
        - actual_detected:    bool

    Returns a dict with all requested cybersecurity metrics.
    """
    tp = tn = fp = fn = 0

    for r in results:
        label = compute_confusion_values(
            r["expected_detection"], r["actual_detected"]
        )
        if label == "TP":
            tp += 1
        elif label == "TN":
            tn += 1
        elif label == "FP":
            fp += 1
        else:
            fn += 1

    total = tp + tn + fp + fn

    detection_rate = tp / max(tp + fn, 1)
    false_positive_rate = fp / max(fp + tn, 1)
    false_negative_rate = fn / max(fn + tp, 1)
    precision = tp / max(tp + fp, 1)
    recall = detection_rate  # same formula
    f1 = (2 * precision * recall) / max(precision + recall, 1e-9)

    return {
        "total_scenarios": total,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "detection_rate": round(detection_rate, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
    }
