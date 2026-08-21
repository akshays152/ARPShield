# ARPShield — ML Anomaly Detection Module

## 1. Purpose

This module provides the **AI/ML component** of ARPShield — an AI-driven ARP spoofing detection and prevention system. It processes ARP network traffic data into structured features and uses an **Isolation Forest** model to detect anomalous network behaviour that may indicate ARP spoofing, scanning, or other Layer 2 attacks.

The module is designed to:
- Consume raw ARP packet observations from the network monitoring module (`network/`)
- Engineer meaningful features from time-windowed traffic
- Train an unsupervised anomaly detection model
- Produce anomaly predictions and scores for downstream risk assessment

## 2. Input Data

### Data Contract

The ML pipeline expects a CSV file of per-packet ARP observations with the following columns:

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | float | Packet capture time (Unix epoch seconds) |
| `op` | int | ARP operation: 1 = request, 2 = reply |
| `src_mac` | string | Source MAC address |
| `dst_mac` | string | Destination MAC address |
| `src_ip` | string | Sender IP address |
| `dst_ip` | string | Target IP address |

This format corresponds to the standard fields extracted from ARP packets via Scapy.

### Current Status

> **Note:** The network monitoring module (`network/`) has not yet produced real captured data. A synthetic data generator (`generate_sample_data.py`) is provided for pipeline development and validation. All synthetic data and any model trained on it are clearly labelled as non-production.

## 3. Feature Engineering

Raw per-packet ARP observations are aggregated into configurable time windows (default: 30 seconds). Each window produces the following 10 features:

| Feature | Description | Anomaly Relevance |
|---------|-------------|-------------------|
| `arp_request_count` | Number of ARP requests in the window | Elevated counts may indicate scanning/probing |
| `arp_reply_count` | Number of ARP replies in the window | Reply floods are a classic spoofing indicator |
| `reply_request_ratio` | Ratio of replies to requests | Values >> 1.0 suggest unsolicited replies (ARP poisoning) |
| `unique_src_macs` | Distinct source MACs | Sudden increase indicates new devices or MAC spoofing |
| `unique_src_ips` | Distinct source IPs | Helps detect IP spoofing or distributed scanning |
| `unique_dst_ips` | Distinct target IPs queried | High values indicate network scanning |
| `ip_mac_pair_count` | Distinct (IP, MAC) pairs | Mapping instability is a direct spoofing signal |
| `max_packets_per_mac` | Max packets from a single MAC | Traffic concentration may indicate flood attack |
| `mac_ip_change_count` | MACs claiming multiple IPs | Primary ARP spoofing indicator |
| `unsolicited_reply_ratio` | Estimated unsolicited reply proportion | Elevated values indicate potential poisoning |

### Features Not Included

- **Gateway mapping changes**: Requires external gateway configuration knowledge not available from per-packet data alone.
- **Historical deviation from baseline**: Requires long-term baseline collection; planned as a future enhancement.

## 4. Why Isolation Forest?

Isolation Forest was selected as the initial anomaly detection model for the following reasons:

1. **Unsupervised**: Does not require labelled attack data, which is unavailable at this stage.
2. **Anomaly-optimised**: Explicitly designed for anomaly detection — it isolates anomalies by building random decision trees and measuring path length (anomalies have shorter paths).
3. **Computationally efficient**: O(n·log n) training complexity; handles the 10-feature space effectively.
4. **Interpretable scores**: The `decision_function` produces continuous anomaly scores, enabling downstream risk assessment with configurable thresholds.
5. **Low false-positive rate**: With proper `contamination` parameter tuning, IF provides a practical balance between sensitivity and specificity.
6. **Proven track record**: Widely used in network intrusion detection research.

## 5. Training Process

```bash
# Step 1: Generate synthetic data (if no real data is available)
python ml/generate_sample_data.py

# Step 2: Engineer features from raw ARP packets
python ml/feature_engineering.py --window 30

# Step 3: Preprocess (handle missing values + scale)
python ml/preprocess.py

# Step 4: Train model
python ml/train.py --contamination 0.05 --n-estimators 100
```

### Configurable Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--contamination` | 0.05 | Expected proportion of anomalies (0 < c ≤ 0.5) |
| `--n-estimators` | 100 | Number of isolation trees in the ensemble |
| `--random-state` | 42 | Random seed for reproducibility |
| `--window` | 30.0 | Feature aggregation window in seconds |

### Training Artifacts

Saved to `ml/models/`:
- `isolation_forest.joblib` — Trained model
- `scaler.joblib` — Fitted StandardScaler
- `feature_config.json` — Feature list, model parameters, and metadata

## 6. Prediction Output

```bash
python ml/predict.py --input ml/data/processed/features.csv
```

For each time window, the prediction module outputs:

| Field | Type | Description |
|-------|------|-------------|
| `anomaly_prediction` | int | 1 = normal, -1 = anomalous |
| `anomaly_score` | float | Continuous score (more negative = more anomalous) |
| `is_anomaly` | bool | True if prediction is -1 |

Output is saved as both **CSV** and **structured JSON** for backend/risk engine consumption.

### JSON Output Format (per window)

```json
{
  "window_start": 1700000030.0,
  "anomaly_prediction": -1,
  "anomaly_score": -0.1234,
  "is_anomaly": true,
  "model_type": "IsolationForest",
  "features": {
    "arp_request_count": 5,
    "arp_reply_count": 42,
    "..."
  }
}
```

## 7. Evaluation Methodology

### Without Labelled Data (Unsupervised Mode)
- Anomaly score distribution analysis
- Normal vs. anomalous score statistics
- Score histogram visualization
- Anomaly rate reporting

### With Labelled Data (Supervised Mode)
When ground-truth labels become available (from controlled test environments):
- Precision, Recall, F1-score
- Confusion matrix (TP, FP, TN, FN)
- False positive rate (FPR)

```bash
python ml/evaluate.py --predictions ml/data/processed/predictions.csv
```

> **Important:** No accuracy/performance numbers are fabricated. The current model is trained on synthetic data for pipeline validation only.

## 8. Limitations

1. **No real training data**: The model is currently trained on synthetic data. Real-world performance is unknown until validated against actual ARP traffic from an authorised test environment.
2. **Unsupervised model**: Isolation Forest detects statistical anomalies, not confirmed ARP spoofing attacks. Anomalous behaviour may have benign causes.
3. **Approximate unsolicited reply detection**: Without session-level request-reply matching, the unsolicited reply metric is an approximation.
4. **No gateway awareness**: The model does not know the network's gateway, so it cannot specifically flag gateway IP spoofing.
5. **Static time window**: The current fixed-window approach may miss attacks that span window boundaries.
6. **No online learning**: The model must be retrained to adapt to network changes.

## 9. Backend Integration

The prediction module outputs structured JSON designed for consumption by the backend/risk engine:

1. **Risk Engine** can use `anomaly_score` as an input signal alongside rule-based detection results.
2. **Dashboard** can display per-window anomaly status and score trends.
3. **Prevention Module** can trigger defensive responses when `is_anomaly` is True and the score exceeds a configurable threshold.

### Integration Points

```python
# Example: importing prediction module programmatically
from ml.predict import load_model_artifacts, predict

model, scaler, config = load_model_artifacts(
    "ml/models/isolation_forest.joblib",
    "ml/models/scaler.joblib",
    "ml/models/feature_config.json",
)

# feature_df is a DataFrame with the 10 model features
result = predict(model, scaler, config, feature_df)
# result contains: anomaly_prediction, anomaly_score, is_anomaly
```

## Directory Structure

```
ml/
├── README.md                  # This documentation
├── generate_sample_data.py    # Synthetic data generator (pipeline validation only)
├── feature_engineering.py     # Raw ARP → windowed ML features
├── preprocess.py              # Missing value handling + scaling
├── train.py                   # Isolation Forest training
├── predict.py                 # Anomaly prediction
├── evaluate.py                # Model evaluation (unsupervised/supervised)
├── models/                    # Trained model artifacts
│   ├── isolation_forest.joblib
│   ├── scaler.joblib
│   └── feature_config.json
└── data/
    ├── sample_arp_data.csv    # Synthetic ARP data
    └── processed/
        ├── features.csv       # Engineered features
        ├── features_scaled.csv
        ├── predictions.csv
        └── predictions.json
```
