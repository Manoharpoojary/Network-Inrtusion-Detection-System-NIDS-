# Implementation Plan — AI-Powered IoT Network Intrusion Detection System

Status: **Phase 1 complete. Evaluation verified against the dataset and notebook. Phase 2 (model loader +
inference service + tests) complete.** See [MODEL_CARD.md](MODEL_CARD.md) for the verified metrics.
Date: 2026-10-22

> **Update after the dataset and notebook were provided** (`src/major_project/training/`):
> - Section 1.6's figure-transcribed metrics are now **reproduced from the artifact itself**.
> - The RF figures (973/27/102/898, AUC 0.987, AP 0.988) are correct for the rule P(attack) ≥ 0.5.
>   The 0.9365 accuracy in the notebook tables comes from `predict()`, which breaks the 4 exact
>   0.5 ties the other way.
> - The test split is 20 % of the same 10,000-row file. It is **not** an independent dataset.
> - Correction to 1.4: `proto_number` is the IANA protocol number (6/17/1) and is consistent with `proto`.
>   It is not random.
> - The notebook removed the leaking `state`/`state_number` columns before training the saved model.
>   Verified: the artifact does not use them.

---

## 1. Repository findings

### 1.1 Current structure

```
major project/
├── .git/                 # repository initialised, NO commits yet; everything untracked
├── .venv/                # uv-managed venv, CPython 3.12.4 (no pip; managed by uv 0.12.0)
├── .gitignore            # Python defaults + .venv
├── .python-version       # 3.12
├── CLAUDE.md             # project instructions
├── README.md             # empty
├── pyproject.toml        # uv project "major-project", build backend uv_build
├── uv.lock
└── src/major_project/
    ├── __init__.py       # hello-world main()
    ├── main.py           # empty
    ├── model/
    │   └── iot_intrusion_rf_pipeline (1).joblib   # 5.7 MB, the trained model
    └── result/           # 13 WhatsApp JPEG exports of evaluation figures
```

- No training code, notebook, dataset CSV, saved test predictions, or raw evaluation data are present.
- No existing backend, frontend, database, or dependency besides the empty uv project.
- Toolchain: Python 3.12.4 in `.venv`, `uv` 0.12.0, Node 22.17.1, npm 10.9.2.

**Only change made during Phase 1:** `uv add` installed `scikit-learn==1.6.1`, `numpy>=2.0,<2.3`,
`pandas>=2.2,<3`, `joblib>=1.4` into the existing `.venv` (recorded in `pyproject.toml` / `uv.lock`)
so the artifact could be inspected. Nothing else was modified.

### 1.2 Model artifact

| Property | Value |
|---|---|
| Path | `src/major_project/model/iot_intrusion_rf_pipeline (1).joblib` |
| SHA-256 | `2557ad7b7b25f76f877f9048889d0de8b062672ea7743e380bcf3e5190173cde` |
| Saved with | scikit-learn **1.6.1**, NumPy **2.x** |
| Object | `sklearn.pipeline.Pipeline` — **complete fitted preprocessing + model** |
| Steps | `preprocessor` = `ColumnTransformer`, `model` = `RandomForestClassifier` |
| Classifier | 100 trees, `max_features="sqrt"`, `max_depth=None`, `random_state=42`, no class weights |
| Training rows | 8,000 (`n_samples_seen_`), class balance ≈ 50/50 |
| `classes_` | `[0, 1]` (int64) |
| `predict_proba` | Available. 100 % of leaves are pure, so probabilities = fraction of trees voting "attack" (steps of 0.01). They are **uncalibrated** model estimates. |

**Load safety.** Before loading, the pickle stream was statically scanned. It references only
`sklearn.*`, `numpy.*`, `joblib.numpy_pickle.*` and one `dill._dill._load_type("slice")`
(an artefact of saving from an environment such as Colab where `dill` was imported; it only
rebuilds built-in `slice` objects). The model was loaded with an **allow-list unpickler**
that rejects any other global and maps that one `dill` call to the built-in `slice`.
The production loader will use the same allow-list plus a SHA-256 check, so `dill` is not a dependency.

### 1.3 Exact input schema (35 columns, this order)

| # | Column | Handling in pipeline |
|---|---|---|
| 1 | `flgs` | categorical → OneHotEncoder, categories `PA`, `S`, `U` |
| 2 | `flgs_number` | numeric → StandardScaler |
| 3 | `proto` | categorical → OneHotEncoder, categories `CoAP, DNS, HTTP, HTTPS, ICMP, MQTT, NTP, RTSP, SMB, SSDP, TCP` |
| 4–35 | `proto_number, sport, dport, pkts, bytes, dur, mean, stddev, sum, min, max, spkts, dpkts, sbytes, dbytes, rate, srate, drate, TnBPSrcIP, TnBPDstIP, TnP_PSrcIP, TnP_PDstIP, TnP_PerProto, TnP_Per_Dport, AR_P_Proto_P_SrcIP, AR_P_Proto_P_DstIP, N_IN_Conn_P_DstIP, N_IN_Conn_P_SrcIP, AR_P_Proto_P_Sport, AR_P_Proto_P_Dport, Pkts_P_State_P_Protocol_P_DestIP, Pkts_P_State_P_Protocol_P_SrcIP` | numeric → StandardScaler |

- After preprocessing: 33 scaled numeric + 3 + 11 one-hot = **47 model features**.
- `OneHotEncoder(handle_unknown="ignore")`: an unseen `flgs`/`proto` value silently becomes an all-zero
  vector. The API will **reject** unknown categories instead, so this never happens silently.
- No imputer in the pipeline: missing or non-finite values must be rejected before inference.
- `remainder="drop"`: extra columns would be silently dropped by sklearn; the API will reject them.

### 1.4 What the training data looked like (from fitted scaler statistics)

| Observation | Consequence |
|---|---|
| **16 numeric features were constant (= 1.0)** in training: `flgs_number` and all 15 `TnBP*/TnP_*/AR_P_*/N_IN_Conn_*/Pkts_P_*` aggregates. | No tree ever splits on them (verified: 15 of 47 transformed features never used). They are required by the schema but have **zero influence** on predictions. |
| `spkts == dpkts`, `sbytes == dbytes`, `srate == drate`, `bytes == sum` (identical mean and variance). | The data are symmetric / derived — not what real bidirectional flows look like. |
| `proto` contains application-layer names (MQTT, CoAP, HTTP…) alongside `proto_number`; `flgs` values `PA`/`S`/`U`. | Encodings differ from Bot-IoT's original (`tcp`/`udp`, `e`, `e s` …). |
| Dataset page (DOI 10.17632/m8swht7tmn.1) states identifiers are synthetic/anonymized. | — |

Top RF importances (global, from the artifact itself; matches your saved figure):
`spkts .153, pkts .134, dpkts .108, bytes .078, sbytes .078, dbytes .076, sum .071, rate .040, srate .038, drate .036, dur .032, dport .025, mean .024, proto_TCP .017, sport .012`.

### 1.5 Target and labels

- Dataset: *Federated IoT/PC Network Traffic Datasets for FTARL IDS* (Mendeley, CC BY 4.0).
  The only labeled IoT file, `iot_devices_dataset_for_testing.csv`, has **10,000 rows** and an
  `attack` column (0/1) — this matches your "10,000 labeled records, 5,000 / 5,000" figure and the
  8,000 training rows in the artifact (80/20 split → 2,000-row test set, 1,000 per class).
- Mapping: **`0 = Benign`, `1 = Attack`** (binary). Supported by the confusion-matrix axis ordering
  (Benign, Attack) and the `attack` column name. Multi-class attack types are **not** supported.

### 1.6 Saved evaluation results (figures only — not re-verified)

Confusion matrices (test set n = 2,000) and derived metrics (computed by me from the matrix counts):

| Model | TN | FP | FN | TP | Accuracy | Precision (attack) | Recall (attack) | F1 (attack) | ROC-AUC* | AP* | Train time* |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Random Forest** | 973 | 27 | 102 | 898 | 0.9355 | 0.9708 | 0.8980 | 0.9330 | 0.987 | 0.988 | 1.04 s |
| XGBoost | 961 | 39 | 99 | 901 | 0.9310 | 0.9585 | 0.9010 | 0.9289 | 0.987 | 0.989 | 2.83 s |
| ANN | 982 | 18 | 111 | 889 | 0.9355 | 0.9802 | 0.8890 | 0.9324 | 0.986 | 0.988 | 25.40 s |
| LSTM | 952 | 48 | 146 | 854 | 0.9030 | 0.9468 | 0.8540 | 0.8980 | 0.966 | 0.972 | 52.63 s |

\* read from figure labels. The bar-chart values are consistent with the matrix-derived numbers.

Caveats:
- These are **transcribed from images**; there is no saved test set or prediction file, so I cannot yet
  confirm they were produced by *this exact* artifact. ROC/PR **curves** cannot be redrawn
  (no underlying points) — the original images can be shown instead.
- A "Top 15 features selected using PCC" figure exists, but the saved pipeline uses **all 35**
  input columns, so PCC selection was not applied to the deployed model.
- Data-leakage / duplicate-across-split checks are impossible without the dataset.

---

## 2. Critical risk: live-capture compatibility

The model was trained on a dataset whose feature semantics cannot be reproduced from real packets:
symmetric src/dst counters, constant aggregate features, app-layer `proto` labels, and an
unspecified flow-aggregation window/units for `dur`, `rate`, `mean`, `stddev`. A Scapy/CICFlowMeter
extractor would produce columns with the same **names** but different **meaning and distribution**,
so predictions on live traffic would be unreliable.

**Plan:** implement the live-monitoring module (capture → bounded queue → flow aggregation →
same validation/inference path) with full start/stop/permission/overflow handling and mocked tests,
but ship it **disabled for inference** (`NIDS_LIVE_INFERENCE_ENABLED=false`) with a written
feature-compatibility report (`docs/LIVE_FEATURE_COMPATIBILITY.md`) that lists every column, how
it would be computed, and why it doesn't match. The dashboard will state this clearly. Offline
CSV analysis is the fully-supported mode.

---

## 3. Proposed architecture

```
Offline (existing, not re-run)          Online (to build)
Dataset CSV ─► preprocessing ─►         CSV upload / JSON API ─► schema validation ─►
RF training ─► evaluation ─►            fitted Pipeline (thread pool) ─► label + P(attack) ─►
iot_intrusion_rf_pipeline.joblib ──────► severity rules ─► explanation ─► SQLite ─► React dashboard
                                         (optional) Scapy capture ─► flow aggregator ─► [gated]
```

### 3.1 Layout (keeps the existing uv package as the single Python source root)

```
src/major_project/
├── model/                    # UNCHANGED — artifact stays where it is
├── result/                   # UNCHANGED — original figures, served read-only
├── __init__.py               # main() → starts uvicorn
├── api/                      # FastAPI routers: health, model, predict, analyze, alerts, dashboard, live
├── core/                     # config (pydantic-settings, env vars), logging, errors
├── schemas/                  # Pydantic request/response models generated from the artifact's schema
├── services/
│   ├── model_loader.py       # allow-list unpickler + SHA-256 check + schema extraction
│   ├── inference.py          # validation, DataFrame build in exact order, predict/proba
│   ├── severity.py           # configurable threshold rules
│   ├── explain.py            # per-prediction explanation (see 3.3)
│   ├── alert_service.py
│   ├── flow_features.py      # live flow aggregator (compatibility-gated)
│   └── capture_service.py    # Scapy capture with bounded queue, stop event
├── database/                 # SQLAlchemy 2.x models, session, init_db
└── evaluation/
    └── reported_metrics.json # transcribed figure values, labeled "reported, unverified"
src/frontend/                 # React + TypeScript + Vite + Tailwind + Recharts + lucide-react
tests/                        # pytest; synthetic fixtures in tests/fixtures/synthetic_*
scripts/                      # e.g. verify_model.py, evaluate_on_csv.py
docs/                         # this plan, ARCHITECTURE.md, MODEL_CARD.md, LIVE_FEATURE_COMPATIBILITY.md
.env.example
```

### 3.2 API (all under `/api`, OpenAPI at `/docs`)

`GET /health`, `GET /model/info`, `POST /predict`, `POST /predict/batch` (≤ 1,000 records),
`POST /analyze/csv` (≤ 10 MB, ≤ 50,000 rows, processed in 1,000-row chunks; returns an analysis id +
results), `GET /analyses/{id}` and `/analyses/{id}/export.csv`, `GET /alerts` (pagination, filters by
severity/label/date/analysis), `GET /alerts/{id}`, `GET /dashboard/summary`, `GET /dashboard/trends`,
`GET /model/performance` (reported metrics, clearly flagged), `GET/POST /live/status|start|stop`
(localhost-only + token, disabled by default).

Validation: exact 35 columns, no missing/extra, numeric finite, categories restricted to the fitted
categories. Inference runs in a thread pool (`run_in_threadpool`) so the event loop is never blocked.

### 3.3 Severity and explanations

- Severity (env-configurable): `info` = predicted benign; `medium` = attack with P(attack) < 0.80;
  `high` = attack with P(attack) ≥ 0.80. Documented as rule-based, not calibrated risk.
- Per-prediction explanation: **SHAP `TreeExplainer`** is exactly compatible with this RF and is
  fast for 100 trees / 47 features (~ms per row). It adds `shap` (+ `numba`) as dependencies.
  Alternative without new deps: tree-path contribution decomposition implemented directly on the
  sklearn trees (mathematically the "Saabas" method). Recommendation: SHAP for single predictions and
  alert details, global importance clearly labeled as global elsewhere. Explanations are mapped back to
  the 35 original columns (one-hot contributions summed per categorical).

### 3.4 Database (SQLite via SQLAlchemy, `NIDS_DATABASE_URL`)

Tables: `analyses` (source type, filename, row counts, timestamps), `predictions` (analysis_id, row
index, label, p_attack, severity, model sha, created_at UTC, selected metadata: proto, flgs, sport,
dport, pkts, bytes, dur), `alerts` (prediction_id, severity, status, explanation JSON),
`monitoring_sessions`. Indexes on created_at, severity, label, analysis_id. No payloads stored.
Schema created with `metadata.create_all` (documented; Alembic can be added for PostgreSQL later).

### 3.5 New dependencies (pinned in `pyproject.toml` via `uv add`)

Runtime: fastapi, uvicorn[standard], pydantic-settings, sqlalchemy, python-multipart, (shap),
scapy (optional extra `live`). Dev: pytest, httpx, ruff. Frontend via npm in `src/frontend`.
No TensorFlow/PyTorch/XGBoost — not needed by the selected RF model.

---

## 4. Test strategy

pytest (no admin or network needed): artifact SHA + allow-list loading (and rejection of a crafted
malicious pickle), schema/order, missing/extra/non-finite/unknown-category rejection, single & batch
prediction, label mapping (0→Benign, 1→Attack), CSV happy-path/oversize/bad-header/bad-type,
alert persistence & retrieval, dashboard aggregates, health with model unavailable (503 on predict),
live capture with mocked sniffer (permission error, stop, queue overflow accounting).
Synthetic rows live only in `tests/fixtures/` and are labeled synthetic. Ruff lint/format.
Frontend: `tsc --noEmit` + `vite build`; manual end-to-end check against the running API.

## 5. Phases

1. ✅ Inspect (this document), then verify the evaluation against the dataset and notebook
   (`scripts/reproduce_evaluation.py`)
2. ✅ Model loader (`services/model_loader.py`) + inference service (`services/inference.py`) +
   tests (48 passing)
3. FastAPI + SQLite + alerts + CSV analysis + tests
4. React dashboard wired to the API
5. Live-monitoring module (gated) + compatibility report + mocked tests
6. README, ARCHITECTURE.md, MODEL_CARD.md, final test/lint run

## 6. Open questions for the project owner

1. ~~Dataset / notebook~~: provided and verified.
2. ~~Live monitoring~~: decided. Build the module, but keep live inference disabled until feature
   compatibility is demonstrated.
3. **Explainability:** OK to add `shap`?
4. **Git baseline:** the repo has no commits. May I make an initial commit of the current state
   before Phase 2 so every later change is reviewable?
