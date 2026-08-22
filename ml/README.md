# ARPShield — ML Anomaly Detection Module

## 1. Purpose

This module provides the **AI/ML component** of ARPShield — an AI-driven ARP spoofing detection and prevention system. It processes ARP network traffic data into structured features and uses an **Isolation Forest** model to detect anomalous network behaviour indicative of ARP spoofing.

The initial dataset contained simulation artifacts and was therefore treated as a **baseline engineering experiment** rather than final model validation. The pipeline is ready for Person 1's improved v2 dataset.

## 2. Architecture

```
RAW ARP DATA (network/final_arp_dataset.csv)
   ↓
TRAIN / TEST SPLIT (stratified, before feature engineering)
   ↓
FEATURE ENGINEERING — fit on train only (FeatureEngineer)
   ↓
TRANSFORM TRAIN → TRANSFORM TEST
   ↓
PREPROCESSING — fit scaler on train only (StandardScaler)
   ↓
TRANSFORM TRAIN → TRANSFORM TEST
   ↓
TRAIN Isolation Forest (unsupervised — labels not used)
   ↓
EVALUATE ON UNSEEN TEST SET
```

## 3. Input Data

### Expected Raw Schema

| Column | Type | Required |
|--------|------|----------|
| `timestamp` | string (ISO datetime) | ✅ |
| `sender_ip` | string | ✅ |
| `sender_mac` | string | ✅ |
| `target_ip` | string | ✅ |
| `target_mac` | string | ✅ |
| `operation` | string ("request" / "reply") | ✅ |
| `label` | int (0=normal, 1=attack) | Optional (for evaluation) |

If v2 changes this schema, the pipeline will fail with a clear error listing the missing columns.

## 4. Feature Engineering

All feature selection is controlled via `ENABLED_FEATURES` in `feature_engineering.py`.

### Currently Enabled Features

| Feature | Category | Stateful | Status |
|---------|----------|----------|--------|
| `operation_encoded` | ARP behaviour | No | Enabled |
| `macs_per_ip` | IP-MAC mapping | **Yes** (fit on train) | Enabled (strong candidate) |
| `sender_ip_frequency` | Frequency | **Yes** (fit on train) | Enabled (strong candidate) |
| `is_broadcast_target` | Packet format | No | Candidate removal |
| `is_unspecified_sender` | Packet format | No | Candidate removal |
| `second` | Timing | No | Candidate removal |
| `is_reply_with_zero_target` | Packet format | No | Candidate removal (artifact) |

### Disabled Features (zero variance in v1 data)

- `hour` — all packets captured at hour 14
- `minute` — all packets captured at minute 52
- `is_unspecified_target` — all zeros

### Features Marked for Removal / Re-evaluation

- **`is_reply_with_zero_target`**: Simulation artifact. 90.1% of v1 attacks have this flag. Real ARP replies always have valid target MACs.
- **`is_broadcast_target`**: Ablation showed removing it improved F1 (+0.10).
- **`is_unspecified_sender`**: Ablation showed removing it improved F1 (+0.09).
- **`second`**: Only 25 unique values in 24-second capture.
- **`hour`, `minute`**: Zero variance.

Feature selection will be finalised after Person 1's v2 dataset is available.

## 5. Data Leakage Prevention

| Risk | Mitigation |
|------|------------|
| Dataset-wide statistics before split | `macs_per_ip` and `sender_ip_frequency` use a stateful `FeatureEngineer` class with explicit `fit()`/`transform()` |
| Scaler fit on full data | `StandardScaler` is fit on training data only |
| Test labels used in training | Assertions verify `label` is never in the feature list |
| Train/test overlap | Assertion verifies no index overlap after split |
| Features depending on test data | `FeatureEngineer.transform()` asserts `is_fitted` before use |

## 6. Isolation Forest

Isolation Forest is an **unsupervised** anomaly detection algorithm. It does not use labels during training. Key properties:

- Isolates anomalies via random recursive partitioning
- Shorter average path length = more anomalous
- `contamination` parameter sets expected anomaly proportion
- `decision_function()` returns continuous anomaly scores
- Labels are used ONLY for post-hoc evaluation

## 7. Prediction Format

```json
{
    "prediction": "anomaly",
    "anomaly_score": -0.0523,
    "is_anomaly": true,
    "model_type": "IsolationForest"
}
```

The prediction module (`predict.py`) loads the exact trained model, scaler, and metadata, enforces the exact feature order from training, and rejects missing features with clear errors.

## 8. Evaluation

The evaluation pipeline (`split_and_evaluate.py`) clearly separates:

- **Training metrics** — informational only, NOT generalisation performance
- **Test metrics** — computed on the held-out, unseen test set

Supported metrics: Accuracy, Precision, Recall, F1-score, False Positive Rate, Confusion Matrix.

## 9. Feature Ablation Framework

The ablation framework in `split_and_evaluate.py` supports predefined experiments:

| Experiment | Description |
|-----------|-------------|
| `baseline` | All enabled features |
| `drop_macs_per_ip` | Remove macs_per_ip |
| `drop_timing` | Remove timing features |
| `drop_suspicious_format` | Remove is_reply_with_zero_target, is_broadcast_target, is_unspecified_sender |
| `core_arp_only` | Only operation_encoded, macs_per_ip, sender_ip_frequency |
| `drop_<feature>` | Auto-generated single-feature drop experiments |

Run with: `python ml/split_and_evaluate.py --ablation`

## 10. Training Reproducibility

All model artifacts are saved to `ml/models/`:

| File | Contents |
|------|----------|
| `isolation_forest.joblib` | Trained model |
| `scaler.joblib` | Fitted StandardScaler |
| `feature_engineer.joblib` | Fitted FeatureEngineer (with learned mappings) |
| `model_metadata.json` | Features, parameters, training info |

## 11. Known Limitations

1. The v1 dataset is a **baseline experiment**, not final validation. The 1,000 simulated attacks contain obvious artifacts.
2. The entire v1 dataset spans only 24 seconds — no meaningful temporal patterns.
3. `is_reply_with_zero_target` is a simulation artifact, not a real ARP property.
4. Current results from v1 data should not be cited as production performance.
5. The pipeline does not support online/incremental learning.

## 12. What Happens When V2 Dataset Arrives

1. Run `split_and_evaluate.py --input <v2_path> --ablation` to re-evaluate.
2. If the schema changes, the pipeline will fail clearly and tell you which columns are missing.
3. Re-evaluate all candidate-removal features with real attack data.
4. Potentially enable `hour`/`minute` if the capture spans multiple hours.
5. Consider removing `is_reply_with_zero_target` if v2 attacks are realistic.
6. Tune `contamination` parameter to match v2's attack proportion.

## Directory Structure

```
ml/
├── README.md                  # This documentation
├── feature_engineering.py     # Feature registry, FeatureEngineer class
├── preprocess.py              # Missing values, scaling
├── train.py                   # Isolation Forest training
├── predict.py                 # Model loading and prediction
├── evaluate.py                # Supervised/unsupervised evaluation
├── split_and_evaluate.py      # Full leakage-free pipeline + ablation
├── generate_sample_data.py    # Synthetic data (pipeline testing only)
├── models/                    # Trained artifacts (git-ignored)
└── data/                      # Processed data (git-ignored)
```
