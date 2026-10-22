# Implementation Plan — AI-Powered IoT Network Intrusion Detection System

Status: **All planned phases are implemented. Section 8 lists what is verified and what is still
open.** Verified metrics are in [MODEL_CARD.md](MODEL_CARD.md).
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

> Superseded in detail by **section 7**, which defines the network-monitoring requirements and
> records the measured feature definitions. The original Phase 1 note follows.

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
- **Per-prediction explanation (decided 2026-10-22, measured on this machine):**

  | Method | Dependency | Latency | Memory | Exactness |
  |---|---|---|---|---|
  | SHAP `TreeExplainer` (path-dependent) | optional extra `explain` (`shap` 0.54.1, ~3 MB, no numba) | ~19 ms/row, linear in rows | +~23 MB RSS | base + Σ SHAP = P(attack), error 4e-13 |
  | Tree-path contributions ("Saabas") | none | ~3 ms/row | negligible | base + Σ = P(attack), exact |

  - SHAP is used when installed; otherwise the tree-path method is used. Every explanation is labelled
    with the method used.
  - Explanations run on the transformed 47 features. One-hot contributions are summed back to the 35
    original columns, and the raw input values are shown alongside.
  - SHAP is computed for single/batch API predictions and for attack alerts, capped per CSV upload; it is
    **not** computed for every benign CSV row (50k rows × 19 ms ≈ 16 min).
  - The UI wording is "features that pushed this model's score up/down". An explanation is **not
    evidence that a flow is malicious**. Global feature importance is shown separately and labelled as
    describing the model overall.

### 3.4 Database (SQLite via SQLAlchemy, `NIDS_DATABASE_URL`)

Tables: `analyses` (source type, filename, row counts, timestamps), `predictions` (analysis_id, row
index, label, p_attack, severity, model sha, created_at UTC, selected metadata: proto, flgs, sport,
dport, pkts, bytes, dur), `alerts` (prediction_id, severity, status, explanation JSON),
`monitoring_sessions`. Indexes on created_at, severity, label, analysis_id. No payloads stored.
Schema created with `metadata.create_all` (documented; Alembic can be added for PostgreSQL later).

### 3.5 New dependencies (pinned in `pyproject.toml` via `uv add`)

Already installed: scikit-learn 1.6.1, numpy 2.2.6, pandas 2.3.3, joblib 1.6.0, pydantic 2.14,
pydantic-settings 2.16, psutil 7.2.2; optional extra `explain`: shap 0.54.1; dev: pytest 8.4, ruff 0.17.

To add: fastapi, uvicorn[standard], sqlalchemy 2.x, python-multipart; scapy as optional extra `capture`;
httpx (dev). Frontend via npm in `src/frontend`.
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

| # | Phase | Status |
|---|---|---|
| 1 | Inspect; verify evaluation against dataset and notebook (`scripts/reproduce_evaluation.py`) | ✅ done |
| 2 | Model loader + inference service + tests (48 passing) | ✅ done |
| 2b | Initial Git commit (3 local commits; artifacts byte-identical, `.gitattributes` prevents EOL rewrites) | ✅ done |
| 3 | Explanation service: SHAP (optional) + tree-path fallback + tests | ✅ done (`2ef9ba2`) |
| 4 | FastAPI + SQLite (health, model info, predict, batch, CSV analysis, alerts, dashboard, model performance) + tests | ✅ done (`eee9cb6`) |
| 5a | Network-interface discovery (psutil) API + tests | ✅ done (`3df381e`) |
| 5b | Offline PCAP analysis → flow aggregation → 35-column extraction + tests | ✅ done (`3df381e`, fix `2f69179`) |
| 5c | Schema validation + training-compatibility report + tests | ✅ done (`3df381e`); verdict: incompatible |
| 5d | Live capture (Scapy, bounded queue, stop, permission handling); inference gated off + mocked tests | ✅ done (`d249c6d`); not yet run on real traffic |
| 6 | React dashboard wired to every endpoint above | ✅ done (`d83250a`); verified by component tests + end-to-end render against the running API |
| 7 | README, ARCHITECTURE.md, LIVE_FEATURE_COMPATIBILITY.md; final test/lint/build run | ✅ done |

The network backend (5a–5d) comes before the frontend so the dashboard's monitoring pages are built
once, against real endpoints.

## 6. Open questions for the project owner

1. ~~Dataset / notebook~~: provided and verified.
2. ~~Live monitoring~~: decided. Build the module, but keep live inference disabled until feature
   compatibility is demonstrated.
3. ~~Explainability~~: SHAP approved as an optional extra; evaluated in 3.3.
4. ~~Git baseline~~: done. Commits `479b57e`, `45ddf5e`, `f1e391a`. Not pushed; there is no remote.

---

## 7. Network-information and monitoring requirements (added 2026-10-22)

### 7.1 Required order

1. Network-interface discovery
2. Offline PCAP analysis
3. Flow-feature extraction and schema validation
4. Comparison against the training feature schema
5. Live packet capture in an authorised test environment
6. Live inference **only after** compatibility is demonstrated

The CSV and JSON inference workflow stays independent of all of the above.

### 7.2 Interface discovery (psutil)

- `psutil.net_if_addrs()`, `net_if_stats()` and `net_io_counters(pernic=True)` supply the name, up/down
  state, MTU, speed and byte/packet/error/drop counters.
- Statistics that aren't supported for an interface are returned as `null`; a failure on one interface
  doesn't fail the request.
- Interface addresses are shown only to the local user. Nothing is persisted.
- Separately, each interface is checked for whether Scapy/Npcap can open it for capture (5d). An
  interface being "up" in psutil does not mean it is capturable.
- On this machine, psutil reports 7 interfaces: Wi-Fi and Loopback are up; Ethernet, Bluetooth and
  "Local Area Connection*" are down; vEthernet (WSL) is up.

### 7.3 Packet capture: platform requirements

| Platform | Requirement / limitation |
|---|---|
| Windows | Scapy needs **Npcap** (https://npcap.com) installed in "WinPcap API-compatible mode". **Verified 2026-10-22: Npcap 1.90 installed, service running, `AdminOnly=0`; a non-admin capture socket opened successfully on Wi-Fi** (`uv run --extra capture python -m major_project.services.capture_diagnostics`). With Npcap's "restrict to administrators" option, the backend must run elevated. Loopback capture needs Npcap's loopback adapter. Wi-Fi capture gives only this host's traffic (no monitor mode). |
| Linux | Root, or `CAP_NET_RAW` + `CAP_NET_ADMIN` on the Python binary. |
| WSL2 | Default NAT networking: WSL sees only the VM's virtual NIC, not the Windows host's Wi-Fi/Ethernet traffic. Mirrored networking mode changes this, but capture still needs root inside WSL. Run capture on Windows (Npcap) to monitor the host. |
| Offline PCAP | No privileges and no Npcap needed (`scapy.utils.PcapReader` streams the file). |

Rules:

- Capture is opt-in per session, on one explicitly selected interface, and only from localhost
  (the API binds to 127.0.0.1; capture endpoints need a local token).
- A BPF filter is optional. Payloads are never stored or logged: only header fields are read, and only to
  update flow counters.
- Capture is never assumed possible on every interface. Each start attempt reports a specific reason
  on failure: no Npcap/libpcap, permission denied, interface not found or down.

### 7.4 Flow-feature extraction: tool decision

| Option | Assessment |
|---|---|
| CICFlowMeter (Java, or the `cicflowmeter` PyPI port) | Emits about 80 CIC-IDS2017 features (`Flow Duration` in µs, `Tot Fwd Pkts`, ...). **None** of the 35 model inputs are produced under the same name and definition. Adds Java, or a Scapy-pinned port, for no benefit. Rejected. |
| Argus (`argus` + `ra`) | The original Bot-IoT tooling, so names match. But this dataset's values do **not** follow Argus definitions (table below), it isn't available natively on Windows, and it would be a second overlapping tool. Rejected. |
| **Small Scapy-based flow aggregator (chosen)** | One tool (Scapy) for both PCAP and live. Bidirectional 5-tuple flows with an idle timeout and an active timeout. Emits exactly the 35 columns in model order, each with a documented formula and a compatibility status per feature. |

### 7.5 Measured feature definitions in the training data (all 10,000 rows)

| Feature | Definition actually present in the data | Reproducible from real packets? |
|---|---|---|
| `pkts`, `bytes`, `dur` (s) | Totals and duration | ✅ (window/timeout semantics unknown) |
| `mean` | `bytes / pkts` (100 %) | ✅ |
| `sum` | `= bytes` (100 %) | ✅ |
| `rate` | `bytes / dur`, **bytes per second** (100 %). Argus uses packets/s. | ✅ |
| `spkts`, `dpkts` | **both** `= pkts // 2` (100 %) | ❌ Real flows are asymmetric. Copying would mean inventing values. |
| `sbytes`, `dbytes`, `srate`, `drate` | **both** `= bytes // 2` (and `/ dur`) | ❌ Same reason |
| `min`, `max` | 40–60 and 500–1000. `mean` lies outside [min, max] on **23.7 %** of rows. | ❌ Physically impossible for packet sizes, so the definition is unknown |
| `stddev` | 0.10–1.50, independent of the size spread | ❌ Definition unknown |
| `flgs` | Determined by protocol: TCP→PA, UDP→U, ICMP→S | ⚠️ Only by copying the dataset's rule, not from real flags |
| `proto` | Application label (HTTP, MQTT, …) fixed to one `dport` each | ⚠️ Port-based guess only |
| `proto_number` | IANA number (6/17/1) | ✅ |
| 15 aggregates + `flgs_number` | Constant 1 | ⚠️ Constant; the model ignores them |

**Consequence:**

- Live and PCAP-extracted features **cannot be made compatible** with this model without inventing
  values: symmetric halves, `min`/`max`/`stddev`.
- The compatibility check (step 4) will therefore report **incompatible**. Live and PCAP flows will be
  shown as *extracted features only, not scored*.
- The inference gate stays closed in code, regardless of `NIDS_LIVE_INFERENCE_ENABLED`, until a
  compatibility report passes.
- Making live inference possible would require retraining on features defined from real flows. That is
  a model change and needs your explicit approval.

### 7.6 Reliability

- **Queue:** a bounded `queue.Queue` (configurable, default 10,000 packets). On overflow, packets are
  counted as dropped and never silently discarded.
- **Flow table:** bounded (default 50,000 active flows). Evicted flows are counted.
- **Malformed or non-IP packets:** counted and skipped.
- **Extractor errors:** counted and logged without packet content.
- **Shutdown:** a stop event plus `AsyncSniffer.stop()` on shutdown, with a join timeout; the session
  status becomes `stopped` or `error` with a reason.
- **Session accounting** (persisted): packets seen / parsed / malformed / dropped, flows emitted /
  evicted, start and stop times (UTC). No IPs, no payloads.
- **PCAP upload:** size limit (default 50 MB) and packet limit (default 1,000,000), streamed rather
  than loaded into memory.

### 7.7 Tests (no admin rights or network needed)

- Interface discovery with mocked psutil: normal, missing stats, psutil error.
- Capture start with mocked Scapy:
  - Npcap/libpcap missing, `PermissionError`, unknown interface;
  - queue overflow accounting, stop and join, clean shutdown.
- Flow aggregator on synthetic packets built in memory with Scapy (labelled synthetic), and on a
  generated PCAP written to `tmp_path`: timeouts, bidirectional keys, formulas, malformed packets.
- Compatibility checker: verifies the incompatible features are reported, and that the inference gate
  refuses to score.

---

## 8. Requirement status (updated 2026-10-22; ✅ = implemented and verified)

| Requirement | Status | Evidence |
|---|---|---|
| Trusted model loads safely (hash pin + allow-list) | ✅ | `tests/test_model_loader.py` |
| Exact 35-feature schema; missing/extra/non-finite/unknown values rejected | ✅ | `tests/test_inference.py`, `tests/test_api_predict.py` |
| Label mapping 0 = Benign, 1 = Attack; explicit threshold | ✅ | notebook + `tests/test_reproduction.py` |
| Verified metrics + ROC/PR data | ✅ | `verified_metrics.json`; held-out CSV through the dashboard proxy reproduced 925 attacks (TN 973 / FP 27 / FN 102 / TP 898) |
| Per-prediction explanations (SHAP optional, tree-path fallback), separate from global importance | ✅ | `tests/test_explain.py` (with and without shap) |
| API: health, model info, importance, predict, batch, CSV + results/export, alerts, dashboard summary/trends | ✅ | `tests/test_api_*.py`; real uvicorn run |
| SQLite persistence; UTC; indexes; restart persistence | ✅ | `tests/test_api_alerts_dashboard.py` |
| Capture diagnostic; psutil interface discovery (no addresses) | ✅ | tests + real run (capture available on Wi-Fi, non-admin) |
| Offline PCAP/PCAPNG analysis; flow extraction; compatibility report | ✅ | `tests/test_network_api.py`, `tests/test_flow_features.py`; real server via proxy |
| Live capture: start/stop/status, bounded queue, drop accounting, clean shutdown, error classification | ✅ (mocked) | `tests/test_capture_service.py`, `tests/test_live_api_security.py` |
| Capture control local-only, optional token, authorisation flag; Origin and upload-size guards | ✅ | `tests/test_live_api_security.py`; checked through the proxy |
| React dashboard on real API data with loading/error/empty states | ✅ | 12 component tests; 5 end-to-end render tests against the running API; production build |
| README, ARCHITECTURE, MODEL_CARD, LIVE_FEATURE_COMPATIBILITY | ✅ | `docs/`, README commands executed |
| Real-traffic PCAP analysed on this machine | ⏳ | needs a user-supplied, authorised capture |
| Live capture session on real traffic | ⏳ | not started (no automatic capture); available on Wi-Fi |
| Visual check in a real browser | ⏳ | not performed (jsdom only) |
| Live inference | ⛔ | blocked by feature incompatibility; needs retraining approval |
