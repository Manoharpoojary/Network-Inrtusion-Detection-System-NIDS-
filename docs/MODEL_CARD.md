# Model Card — IoT Intrusion Detection Random Forest

Last verified: 2026-10-22 with `scripts/reproduce_evaluation.py`
(output: `src/major_project/evaluation/verified_metrics.json`).

## 1. Summary

| | |
|---|---|
| Task | Binary classification of one flow record: **Benign (0)** vs **Attack (1)** |
| Model | scikit-learn `Pipeline`: `ColumnTransformer` (StandardScaler + OneHotEncoder) → `RandomForestClassifier(n_estimators=100, random_state=42)`, other parameters default |
| Artifact | `src/major_project/model/iot_intrusion_rf_pipeline (1).joblib` |
| SHA-256 | `2557ad7b7b25f76f877f9048889d0de8b062672ea7743e380bcf3e5190173cde` |
| Model version string | `rf-2557ad7b7b25` |
| Built by | `training/Untitled2.ipynb`, cell 33 (`final_pipeline.fit(X_train, y_train)`) |
| Library versions | scikit-learn 1.6.1 (pickle and runtime match; no version warning), NumPy 2.x |
| Output | `predict_proba` → P(attack) = fraction of the 100 trees voting attack (every leaf is pure). **Not calibrated.** |
| Not supported | Attack-type (multi-class) classification, although the data has `category`/`subcategory` |

## 2. Data

- **Source:** *Federated IoT/PC Network Traffic Datasets for FTARL IDS*, Mendeley Data,
  DOI 10.17632/m8swht7tmn.1, CC BY 4.0. The provider describes IPs/identifiers as synthetic or
  anonymised.
- **File used:** the provider's labelled IoT file, 10,000 rows × 46 columns. It is present in this repo as
  `src/major_project/training/iot_intrusion_predictions.csv`, which adds two columns appended by the notebook:
  `Prediction` and `Attack Probability (%)`.
  SHA-256 `9742aa887c7cfc9c405bbceb0b10ec959053347d14ef3ffef8093bb50bc5c6de`.
- **Classes:** 5,000 Benign / 5,000 Attack. Attack categories: DoS 1,875, DDoS 1,250, Reconnaissance 1,250,
  Theft 625.
- No missing values, no duplicate rows, no duplicate feature vectors.

### Properties of the data that limit how far results generalise

| Property | Evidence |
|---|---|
| All 5,000 attack rows come from one source IP (`192.168.100.147`); benign rows come from six others. | Notebook cell 35 |
| `state` = `ATTACK` / `state_number` = 2 on every attack row, and only on attack rows. | Notebook cell 13 |
| Rows are ordered by label: all benign `pkSeqID`s are ≤ 30000, all attack IDs > 30000. | Notebook cells 39–43 |
| Every row has the same `stime`/`ltime` (`07-06-2025 10:36`). | Notebook cell 29 |
| 15 aggregate features (`TnBP*`, `TnP_*`, `AR_P_*`, `N_IN_Conn_*`, `Pkts_P_*`) and `flgs_number` are always 1. | Scaler variance = 0 |
| `spkts == dpkts`, `sbytes == dbytes`, `srate == drate`, `bytes == sum` on every row. | Scaler statistics, dataset |
| Values are tightly bounded, e.g. `pkts` 5–100, `bytes` 300–9,998, `dur` 0.01–2.5 s. | Dataset |

These properties suggest the data are synthetic or heavily templated, not raw captured flows.

## 3. Features (35 inputs, in this exact order)

`flgs, flgs_number, proto, proto_number, sport, dport, pkts, bytes, dur, mean, stddev, sum, min, max, spkts,
dpkts, sbytes, dbytes, rate, srate, drate, TnBPSrcIP, TnBPDstIP, TnP_PSrcIP, TnP_PDstIP, TnP_PerProto,
TnP_Per_Dport, AR_P_Proto_P_SrcIP, AR_P_Proto_P_DstIP, N_IN_Conn_P_DstIP, N_IN_Conn_P_SrcIP,
AR_P_Proto_P_Sport, AR_P_Proto_P_Dport, Pkts_P_State_P_Protocol_P_DestIP, Pkts_P_State_P_Protocol_P_SrcIP`

- **Categorical (one-hot):**
  - `flgs` ∈ {PA, S, U}
  - `proto` ∈ {CoAP, DNS, HTTP, HTTPS, ICMP, MQTT, NTP, RTSP, SMB, SSDP, TCP}
  - `proto_number` is the IANA number consistent with `proto`: 6 = TCP-based, 17 = UDP-based, 1 = ICMP.
- **Numeric (standardised):** the remaining 33 columns.
- **Columns removed before training (notebook cell 14):**
  - The target `attack`, and `category`/`subcategory`, which are derived from the label.
  - Identifiers and timestamps: `pkSeqID, stime, ltime, saddr, daddr, seq`.
  - The leaking `state, state_number`. Including them gave 100 % test accuracy (cell 10).
- **Constant inputs:** the 16 constant columns above are required by the pipeline, but no tree ever splits
  on them, so their values never change a prediction.
- **Global importance (top 10, from the artifact):** spkts .153, pkts .134, dpkts .108, bytes .078,
  sbytes .078, dbytes .076, sum .071, rate .040, srate .038, drate .036.

## 4. Evaluation methodology (reproduced)

1. Load the 10,000-row file and drop the columns listed in section 3.
2. Run `train_test_split(test_size=0.20, random_state=42, stratify=attack)` → 8,000 train / 2,000 test
   (1,000 per class).
3. Score the **saved artifact** on the 2,000 test rows. Nothing is refitted.

Integrity checks (all from `verified_metrics.json`):

| Check | Result |
|---|---|
| Artifact's scaler mean/variance equal to the 8,000 training rows (not the full data) | ✅ preprocessing fitted on training data only |
| Re-fitting the notebook recipe in a scratch session | Produces **bit-identical** probabilities |
| Test rows identical to a training row | 0 |
| Training accuracy | 1.000 (fully grown trees) |
| Exact P(attack) = 0.5 ties in the test set | 4 |
| Independent test set? | **No.** Train and test come from the same file and capture. |

## 5. Verified test metrics (n = 2,000)

The application labels a flow **Attack when P(attack) ≥ 0.5**. That threshold is configurable via
`NIDS_ATTACK_THRESHOLD` and is the rule used for the notebook's final evaluation and the saved figures.

| Decision rule | TN | FP | FN | TP | Accuracy | Attack precision | Attack recall | Attack F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| **P(attack) ≥ 0.5 (application default)** | 973 | 27 | 102 | 898 | **0.9355** | 0.9708 | 0.8980 | 0.9330 | 0.027 |
| `pipeline.predict()` (ties → Benign) | 976 | 24 | 103 | 897 | 0.9365 | 0.9739 | 0.8970 | 0.9339 | 0.024 |

Threshold-independent: **ROC-AUC 0.9871**, **Average precision 0.9881**.

## 6. Comparison with the previously shared figures

| Figure / value | Status |
|---|---|
| RF confusion matrix 973 / 27 / 102 / 898 | ✅ Reproduced exactly (≥ 0.5 rule) |
| RF ROC-AUC 0.987, AP 0.988 | ✅ Reproduced (0.9871 / 0.9881) |
| RF accuracy 0.9365 in notebook tables (cells 20–22, 32, 48) | ⚠️ Comes from `predict()`. The figures use ≥ 0.5 → 0.9355. Both are the same model and differ only on the 4 tied rows (3 benign, 1 attack). |
| RF precision/recall/F1 "97 / 90 / 93" in tables | ⚠️ Rounded values from `classification_report`; exact values in section 5 |
| Feature-importance figure | ✅ Matches the artifact's `feature_importances_` |
| "Top 15 features using PCC" figure | ⚠️ Correct for the PCC experiment, but **the deployed model uses all 35 inputs, not the PCC subset**. PCC lowered RF accuracy to 0.926 (cell 26). |
| Class distribution 5,000 / 5,000 | ✅ |
| XGBoost / ANN / LSTM metrics and curves | ℹ️ Taken from notebook outputs (cell 55); not re-run here, since XGBoost and TensorFlow are not installed in this environment and those models were not saved |
| Training-time chart (1.04 / 2.83 / 25.40 / 52.63 s) | ⚠️ **Hard-coded** in cell 62. Does not match the times printed in the saved outputs (RF 1.01 s, XGB 0.76 s, ANN 31.50 s, LSTM 47.49 s). Single Colab wall-clock runs, so treat as indicative only. |

Notebook-reported comparison (cell 55, same split, ≥ 0.5 rule):

| Model | Accuracy | Attack precision | Attack recall | Attack F1 | ROC-AUC | AP |
|---|---|---|---|---|---|---|
| Random Forest | 0.9355 | 0.9708 | 0.8980 | 0.9330 | 0.9871 | 0.9881 |
| XGBoost | 0.9310 | 0.9585 | 0.9010 | 0.9289 | 0.9874 | 0.9886 |
| ANN | 0.9355 | 0.9802 | 0.8890 | 0.9324 | 0.9862 | 0.9878 |
| LSTM | 0.9030 | 0.9468 | 0.8540 | 0.8980 | 0.9665 | 0.9722 |

The Random Forest row was independently re-verified. The other rows are as reported by the notebook.
RF, XGBoost and ANN are within about 0.5 percentage points of each other. One random split cannot
separate them reliably; no cross-validation or confidence intervals were computed.

## 7. Intended use and limitations

- **Intended use:** an academic demonstration of ML-based intrusion detection on flow records that use
  the **same feature definitions and encodings as this dataset**, via CSV upload or the JSON API.
- **Not validated on real network traffic.** All metrics are from one synthetic-looking capture, with a
  single attacker IP and templated feature values. Real-world performance is unknown and likely lower.
- **Live capture:**
  - Packets captured with Scapy or CICFlowMeter would not reproduce this dataset's semantics: mirrored
    src/dst counters, constant aggregate features, app-level `proto` labels and an unspecified flow window.
  - Live-flow inference is therefore **disabled** (`NIDS_LIVE_INFERENCE_ENABLED=false`) until
    compatibility is demonstrated.
- **Probabilities:** P(attack) is a vote fraction, not a calibrated probability. Alert severity is
  rule-based and is not a measure of real-world risk.
- **Threshold:** the reported metrics depend on the threshold rule (section 5).
- **Explanations:** global feature importance describes the model overall. It does not explain an
  individual prediction.

## 8. Safe loading

The artifact is loaded by `major_project.services.model_loader.load_model`. It applies two checks:

- **SHA-256 pin:** the file's hash must match the trusted value.
- **Restricted unpickler:** only allow-listed globals are resolved: scikit-learn classes, NumPy
  array/scalar types, joblib's array wrapper and `slice`. Anything else is blocked, including inside
  nested object arrays.

The pickle contains one `dill._dill._load_type("slice")` reference, because it was saved in Colab after
`dill` had been imported. The loader maps that reference to the built-in `slice`, so `dill` is not a
dependency.
