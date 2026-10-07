import sys
from pathlib import Path

import pandas as pd


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DETECTION_ROOT = PROJECT_ROOT / "detection" / "arp-detection"
DATASET_PATH = PROJECT_ROOT / "network" / "final_arp_dataset.csv"
BASELINE_PATH = DETECTION_ROOT / "config" / "trusted_baseline.json"

# Make Person 2's detection package importable.
sys.path.insert(0, str(DETECTION_ROOT))

from detection_engine.detector import ARPSpoofDetector


# ---------------------------------------------------------
# Dataset -> ARPShield packet adapter
# ---------------------------------------------------------
def row_to_packet(row):
    opcode = int(row["arp_opcode"])

    if opcode == 1:
        operation = "request"
    elif opcode == 2:
        operation = "reply"
    else:
        operation = str(row["arp_type"]).lower()

    return {
        "timestamp": float(row["timestamp"]),
        "src_mac": str(row["source_mac"]),
        "src_ip": str(row["source_ip"]),
        "dst_mac": str(row["destination_mac"]),
        "dst_ip": str(row["destination_ip"]),
        "op": operation,
    }


# ---------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------
def main():
    print("=" * 70)
    print("ARPShield - HCRL ARP Dataset Evaluation")
    print("=" * 70)

    print(f"Dataset: {DATASET_PATH}")
    print(f"Rows: loading...")
    print()

    df = pd.read_csv(DATASET_PATH)
    
    # Quick integration test: process a representative subset.
    df = df.sort_values("timestamp").head(1000).reset_index(drop=True)

    print(f"Total records: {len(df):,}")
    print("\nGround-truth labels:")
    print(df["label"].value_counts().to_string())

    print("\nARP types:")
    print(df["arp_type"].value_counts().to_string())

    print("\nCreating detector...")
    detector = ARPSpoofDetector(
        baseline_path=str(BASELINE_PATH)
    )

    total_packets = 0
    detected_packets = 0
    attack_packets = 0
    normal_packets = 0

    true_positive = 0
    false_positive = 0
    false_negative = 0
    true_negative = 0

    rule_counts = {}
    severity_counts = {}

    print("\nProcessing HCRL records...")

    for _, row in df.iterrows():
        packet = row_to_packet(row)
        alerts = detector.process(packet)

        is_attack = str(row["label"]).strip().lower() == "attack"
        detected = len(alerts) > 0

        total_packets += 1

        if is_attack:
            attack_packets += 1
            if detected:
                true_positive += 1
            else:
                false_negative += 1
        else:
            normal_packets += 1
            if detected:
                false_positive += 1
            else:
                true_negative += 1

        if detected:
            detected_packets += 1

        for alert in alerts:
            rule = alert.get("rule", "unknown")
            severity = alert.get("severity", "unknown")

            rule_counts[rule] = rule_counts.get(rule, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # -----------------------------------------------------
    # Metrics
    # -----------------------------------------------------
    detection_rate = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative)
        else 0
    )

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0
    )

    recall = detection_rate

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0
    )

    accuracy = (
        (true_positive + true_negative) / total_packets
        if total_packets
        else 0
    )

    false_positive_rate = (
        false_positive / (false_positive + true_negative)
        if (false_positive + true_negative)
        else 0
    )

    false_negative_rate = (
        false_negative / (false_negative + true_positive)
        if (false_negative + true_positive)
        else 0
    )

    # -----------------------------------------------------
    # Results
    # -----------------------------------------------------
    print("\n" + "=" * 70)
    print("HCRL EVALUATION RESULTS")
    print("=" * 70)

    print(f"\nTotal packets:       {total_packets:,}")
    print(f"Attack packets:      {attack_packets:,}")
    print(f"Normal packets:      {normal_packets:,}")
    print(f"Packets detected:    {detected_packets:,}")

    print("\nConfusion Matrix:")
    print(f"  True Positives:    {true_positive:,}")
    print(f"  True Negatives:    {true_negative:,}")
    print(f"  False Positives:   {false_positive:,}")
    print(f"  False Negatives:   {false_negative:,}")

    print("\nMetrics:")
    print(f"  Accuracy:           {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"  Detection Rate:     {detection_rate:.4f} ({detection_rate * 100:.2f}%)")
    print(f"  Precision:          {precision:.4f} ({precision * 100:.2f}%)")
    print(f"  Recall:             {recall:.4f} ({recall * 100:.2f}%)")
    print(f"  F1 Score:           {f1:.4f} ({f1 * 100:.2f}%)")
    print(f"  False Positive Rate:{false_positive_rate:.4f} ({false_positive_rate * 100:.2f}%)")
    print(f"  False Negative Rate:{false_negative_rate:.4f} ({false_negative_rate * 100:.2f}%)")

    print("\nDetection rules triggered:")
    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
        print(f"  {rule:30s} {count:,}")

    print("\nSeverity distribution:")
    for severity, count in sorted(severity_counts.items(), key=lambda x: -x[1]):
        print(f"  {severity:15s} {count:,}")

    print("\n" + "=" * 70)
    print("HCRL evaluation complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()