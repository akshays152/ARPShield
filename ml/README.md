# ARPShield — ML Anomaly Detection Module

## 1. Purpose

This module provides the **AI/ML component** of ARPShield — an AI-driven ARP spoofing detection and prevention system. It processes ARP network traffic data into structured features and uses an **Isolation Forest** model to detect anomalous network behaviour that may indicate ARP spoofing or other Layer 2 attacks.

The module is designed to:
- Consume raw ARP packet observations from the network monitoring module (`network/`)
- Engineer meaningful per-packet features from captured traffic
- Train an unsupervised anomaly detection model
- Produce anomaly predictions and scores for downstream risk assessment
- Evaluate detection quality when labelled data is available

## 2. Input Data

### Data Source

The ML pipeline consumes data produced by **Person 1's network monitoring module** (`network/`). Person 1 has provided:

- **`network/arp_dataset.csv`** — 5,000 real captured ARP packets
- **`network/simulated_attack.csv`** — 1,000 simulated ARP spoofing packets
- **`network/final_arp_dataset.csv`** — 6,000 combined records with labels (0=normal, 1=attack)

### Data Format (Person 1's schema)

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | string | Capture time (ISO format, e.g. `2026-08-20 14:52:06`) |
| `sender_ip` | string | Source/sender IP address |
| `sender_mac` | string | Source/sender MAC address |
| `target_ip` | string | Target IP address |
| `target_mac` | string | Target MAC address |
| `operation` | string | ARP operation: `"request"` or `"reply"` |
| `label` | int | 0 = normal traffic, 1 = simulated attack (in `final_arp_dataset.csv`) |

## 3. Feature Engineering

Raw per-packet ARP observations are converted into 10 engineered features. The module supports two modes:

### Per-Packet Features (Primary — aligns with Person 1's approach)

| Feature | Description | Anomaly Relevance |
|---------|-------------|-------------------|
| `operation_encoded` | ARP op as integer: 0=request, 1=reply | Attacks use reply packets |
| `is_broadcast_target` | Target MAC is broadcast (ff:ff:ff:ff:ff:ff) | Suspicious for unsolicited replies |
| `is_unspecified_target` | Target IP is 0.0.0.0 | ARP probes; unusual in normal traffic |
| `is_unspecified_sender` | Sender IP is 0.0.0.0 | DHCP probes; unusual otherwise |
| `macs_per_ip` | Unique MACs per sender IP (dataset-wide) | **Primary spoofing signal**: >1 means multiple MACs claim same IP |
| `sender_ip_frequency` | How often this sender IP appears | Flooding/scanning indicator |
| `hour` | Hour of day from timestamp | Temporal attack patterns |
| `minute` | Minute from timestamp | Temporal attack patterns |
| `second` | Second from timestamp | Temporal attack patterns |
| `is_reply_with_zero_target` | Reply with zero target MAC | Suspicious: legitimate replies have valid target MAC |

### Windowed Features (Complementary mode)

Available via `--mode windowed`. Aggregates packets into time windows for temporal pattern detection. Features include request/reply counts, reply ratio, unique entities, IP-MAC mapping instability, and unsolicited reply estimation.

## 4. Why Isolation Forest?

Isolation Forest was selected as the anomaly detection model for:

1. **Anomaly-optimised**: Explicitly designed for anomaly detection by isolating outliers via random partitioning (shorter isolation path = more anomalous).
2. **Works without labels**: Can be trained unsupervised, important for real deployments where attack labels don't exist.
3. **Computationally efficient**: O(n·log n) training; handles the 10-feature space effectively.
4. **Interpretable scores**: `decision_function` produces continuous anomaly scores enabling configurable risk thresholds.
5. **Low false-positive rate**: 6.78% FPR achieved on Person 1's dataset.
6. **Proven in network security**: Widely used in intrusion detection research.

## 5. Training Process

```bash
# Step 1: Engineer features from Person 1's captured data
python ml/feature_engineering.py --input network/final_arp_dataset.csv

# Step 2: Preprocess (handle missing values + scale)
python ml/preprocess.py

# Step 3: Train model (contamination matches attack ratio in dataset)
python ml/train.py --contamination 0.167

# Step 4: Predict
python ml/predict.py

# Step 5: Evaluate
python ml/evaluate.py
```

### Configurable Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--contamination` | 0.05 | Expected proportion of anomalies (0 < c ≤ 0.5). Set to 0.167 for Person 1's data |
| `--n-estimators` | 100 | Number of isolation trees in the ensemble |
| `--random-state` | 42 | Random seed for reproducibility |
| `--mode` | per-packet | Feature mode: `per-packet` or `windowed` |

### Training Artifacts

Saved to `ml/models/`:
- `isolation_forest.joblib` — Trained model
- `scaler.joblib` — Fitted StandardScaler
- `feature_config.json` — Feature list, model parameters, metadata

## 6. Prediction Output

```bash
python ml/predict.py --input ml/data/processed/features.csv
```

For each packet, the prediction module outputs:

| Field | Type | Description |
|-------|------|-------------|
| `anomaly_prediction` | int | 1 = normal, -1 = anomalous |
| `anomaly_score` | float | Continuous score (more negative = more anomalous) |
| `is_anomaly` | bool | True if prediction is -1 |

Output is saved as both **CSV** and **structured JSON** for backend/risk engine consumption.

## 7. Evaluation Results

### Supervised Evaluation (Person 1's labelled data: 5,000 normal + 1,000 attack)

| Metric | Value |
|--------|-------|
| **Accuracy** | 88.73% |
| **Precision** | 66.17% |
| **Recall** | 66.30% |
| **F1-score** | 66.23% |
| **False Positive Rate** | 6.78% |

### Confusion Matrix

|  | Predicted Normal | Predicted Anomaly |
|--|-----------------|-------------------|
| **True Normal** | 4,661 (TN) | 339 (FP) |
| **True Attack** | 337 (FN) | 663 (TP) |

### Interpretation

- The model achieves **88.73% overall accuracy** with a low **6.78% false positive rate**
- It correctly identifies **66.3% of attacks** (recall) while maintaining high precision
- Normal traffic classification is strong at **93% precision/recall**
- The Isolation Forest works well as a first-line anomaly detector, with room for improvement via ensemble methods or supervised classifiers

## 8. Limitations

1. **Unsupervised model on labelled data**: Isolation Forest doesn't use labels during training — a supervised model (e.g., Random Forest) could potentially achieve higher recall on this specific dataset.
2. **Simulated attack data**: The attack portion of the dataset is simulated (not from real attacks), so real-world performance may differ.
3. **Low temporal variance**: All packets were captured within the same minute, so time-based features (`hour`, `minute`) provide no discriminative power in this dataset.
4. **No gateway awareness**: The model doesn't know the network's gateway IP, limiting its ability to specifically flag gateway spoofing.
5. **Training on full dataset**: For rigorous evaluation, a train/test split should be used. Current results are on the training set.
6. **No online learning**: The model must be retrained to adapt to network changes.

## 9. Backend Integration

The prediction module outputs structured JSON designed for consumption by the backend/risk engine:

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
├── generate_sample_data.py    # Synthetic data generator (for when real data unavailable)
├── feature_engineering.py     # Raw ARP → per-packet/windowed ML features
├── preprocess.py              # Missing value handling + scaling
├── train.py                   # Isolation Forest training
├── predict.py                 # Anomaly prediction
├── evaluate.py                # Model evaluation (unsupervised/supervised)
├── models/                    # Trained model artifacts
│   ├── isolation_forest.joblib
│   ├── scaler.joblib
│   └── feature_config.json
└── data/
    └── processed/
        ├── features.csv
        ├── features_scaled.csv
        ├── predictions.csv
        ├── predictions.json
        ├── evaluation_metrics.json
        ├── confusion_matrix.png
        └── score_distribution_by_label.png
```
