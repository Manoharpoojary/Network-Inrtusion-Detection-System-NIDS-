# Architecture

## 1. Overview

```text
                    OFFLINE (existing work, not re-run by the app)
  Mendeley CSV ──► notebook: drop label/ID/leaking columns ──► 80/20 stratified split
               ──► fit ColumnTransformer + RandomForest on train ──► iot_intrusion_rf_pipeline.joblib
                                                     │
                     scripts/reproduce_evaluation.py │ (re-scores the artifact; no retraining)
                                                     ▼
                                     evaluation/verified_metrics.json

                    ONLINE (this application)
 ┌────────────────────────── React dashboard (src/frontend, Vite dev/preview server) ──────────────────────────┐
 │ Overview · Analyze · Alerts · Model performance · Network & capture · System          /api proxied ▼        │
 └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 ┌──────────────────────────────── FastAPI (src/major_project, 127.0.0.1:8000) ─────────────────────────────┐
 │ middleware: CORS (dashboard origin) · Origin/size guard · request logging · JSON error handlers          │
 │                                                                                                          │
 │ JSON / CSV ──► validation ──► fitted pipeline ──► P(attack) ──► threshold ──► severity ──► SQLite        │
 │ (FlowFeatures   (InferenceService)  (thread pool)                 rules        (analyses, predictions,   │
 │  + CSV parser)                                         └─► explanations (SHAP / tree path)   alerts)      │
 │                                                                                                          │
 │ PCAP upload ─┐                                                                                           │
 │ live capture ┴─► header parsing ─► flow aggregation ─► model-input candidates (gaps left empty)          │
 │  (Scapy)          (no payloads)     (bounded)          ─► compatibility report ─► network_runs           │
 │                                                        ─► inference gate: CLOSED (no path to the model)  │
 └──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Backend modules (`src/major_project/`)

| Module | Responsibility |
|---|---|
| `core/config.py` | `Settings` from `NIDS_*` environment variables / `.env`; limits, thresholds, paths |
| `core/logging.py` | JSON-lines logging with an allow-list of fields (no request bodies, features or payloads) |
| `services/model_loader.py` | SHA-256 check, restricted unpickler (sklearn/numpy/joblib only), schema extraction |
| `services/inference.py` | Strict validation of records/frames; chunked `predict_proba`; threshold; warnings |
| `services/explain.py` | Local explanations (SHAP TreeExplainer, or vectorised tree-path contributions); global importance |
| `services/severity.py` | Configurable rule: Benign → informational; Attack → medium / high |
| `services/recording.py` | Runs predictions and persists analyses, predictions, alerts and eager explanations |
| `services/csv_analysis.py` | Upload limits, encoding, duplicate headers, whole-file validation in chunks |
| `services/flow_features.py` | Header-only packet parsing; bidirectional flow aggregation with timeouts and a bounded flow table |
| `services/compatibility.py` | Per-feature rules, invariant comparison, schema validation, inference gate |
| `services/pcap_analysis.py` | Streams PCAP/PCAPNG from memory; counts non-IP, malformed and truncated records |
| `services/capture_service.py` | Live capture lifecycle (see §4) |
| `services/capture_diagnostics.py`, `services/interfaces.py` | Scapy/Npcap checks; psutil interface state and counters |
| `schemas/flow.py` | `FlowFeatures`: the 35 inputs with strict types; checked against the artifact at start-up |
| `api/` | Routers (`system`, `predict`, `analyses`, `alerts`, `dashboard`, `network`), dependencies, security, error handlers |
| `database/` | SQLAlchemy models, session management, read queries |

Request handlers that do blocking work (inference, uploads, PCAP parsing) are plain `def` functions,
so FastAPI runs them in its thread pool and the event loop is never blocked.

## 3. Inference path

1. **Validation:** `FlowFeatures` (Pydantic, strict) rejects missing or extra fields, wrong types,
   NaN/∞, negative values, bad ports and unknown categories. `InferenceService` checks again; it is
   the only path for CSV.
2. **Prediction:** columns are put in the model's order, and the fitted pipeline computes
   `predict_proba` in chunks of 5,000 rows.
3. **Labelling:** `label = Attack if P(attack) ≥ NIDS_ATTACK_THRESHOLD` (0.5). This reproduces the
   reported evaluation.
4. **Severity and alerts:** each prediction gets a severity, and an alert is created for medium/high.
   The 35 validated inputs are stored with the alert for review and later explanation.
5. **Explanations:** computed eagerly up to `NIDS_MAX_EAGER_EXPLANATIONS` per request; the rest are
   computed and cached when an alert is first opened.
6. **Persistence:** a CSV upload is all-or-nothing. Every chunk is validated before the first
   prediction is stored.

## 4. Live capture (`LiveCaptureManager`)

```text
Scapy AsyncSniffer thread                      worker thread ("capture-worker")
  prn(packet) ─► packet_meta(): headers only     loop until stop / max duration / sniffer error:
            ─► queue.put_nowait(meta)              meta = queue.get(timeout=0.2) ─► FlowAggregator.add
               full? ─► dropped_queue_full += 1    every 1 s: expire idle flows (wall clock)
                                                   sniffer.exception? ─► classify, stop
                                                 finish: sniffer.stop() ─► drain queue ─► flush flows
                                                         ─► compatibility report ─► persist network_run
```

- One session runs at a time. The states are `stopped → starting → running → stopping → stopped | error`.
- Sniffer start-up errors appear asynchronously in `sniffer.exception`. The manager waits briefly
  after `start()`, then classifies them as `permission_denied`, `interface_not_found`, `driver_error`
  or `capture_error`.
- **Memory is bounded.** The queue (default 10,000 packet records), the active flow table (50,000)
  and the recent-flow buffer (200) are all capped. Every drop and eviction is counted.
- **Shutdown:** the application lifespan calls `shutdown()`, so a running capture always stops cleanly.
- **No prediction path.** The manager has no reference to the predictor. It uses the validator only
  for schema checks, and tests assert this.

## 5. Data model (SQLite via SQLAlchemy 2)

| Table | Key columns | Indexes |
|---|---|---|
| `analyses` | id (uuid), source (`api_single`/`api_batch`/`csv`), filename (sanitised), counts, model_version, threshold, ignored_columns | source, created_at |
| `predictions` | analysis_id, row_index, label, attack_probability, severity, model_version, proto, flgs, sport, dport, pkts, bytes, dur | created_at, label, severity, (analysis_id, row_index) |
| `alerts` | prediction_id (unique), analysis_id, severity, status, attack_probability, proto, dport, features_json, explanation_json | created_at, severity, status, proto, analysis_id |
| `network_runs` | kind (`pcap`/`live`), status, packet/flow counters, dropped_packets, compatible, stats_json, report_json | kind, created_at |

- **Timestamps** are stored as UTC and returned timezone-aware.
- **No sensitive network data:** no IP addresses, MAC addresses or payloads are stored.
- **Schema setup:** tables are created idempotently at start-up. Switching to PostgreSQL means
  changing `NIDS_DATABASE_URL` and adding Alembic. The trends query has a PostgreSQL branch
  (`date_trunc`).

## 6. Security controls

| Concern | Control |
|---|---|
| Malicious model file | SHA-256 pin + allow-list unpickler, including nested object arrays |
| Remote capture control | `require_local_client` (127.0.0.1/::1) on capture endpoints; optional `X-Capture-Token` (constant-time compare); `authorized: true` required |
| Cross-site requests | CORS restricted to the dashboard origin; middleware rejects state-changing requests with a foreign `Origin` |
| Large uploads | `Content-Length` checked before multipart parsing; byte, row, packet and flow limits while reading |
| Injection | Parameterised SQLAlchemy queries; BPF filter character allow-list (passed to libpcap, never a shell) |
| Information leakage | Generic 500 responses; stack traces only in logs; logs without feature values |
| User paths | Upload filenames are sanitised display strings, never used as filesystem paths; PCAPs read from memory |

## 7. Frontend (`src/frontend/`)

- **Stack:** React 19, TypeScript, Vite 8 and Tailwind CSS 4. Charts use Recharts, with colours
  validated for colour-vision deficiency on the dark surface. Icons are lucide-react.
- **API layer:** `src/api/client.ts` is a typed `fetch` wrapper that maps the backend's error format
  to `ApiError`. `src/api/types.ts` mirrors the backend response models.
- **Data loading:** `useApi` loads data, ignores superseded responses and exposes `reload`;
  `usePolling` refreshes live capture status every 2 s while a session is active.
- **Pages:** hash-routed and lazy-loaded. Every page has loading, error (with retry) and empty states.
- **Proxy:** in development and preview, Vite proxies `/api` to the backend. The browser therefore
  talks to a single origin, and the backend sees a local client.
