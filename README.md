# AI-Powered IoT Network Intrusion Detection System

A final-year BTech project. It serves a trained **Random Forest** model behind a FastAPI backend and a
React dashboard. The model classifies IoT network **flow-feature records** as **Benign** or **Attack**.
The project also includes offline PCAP analysis and a controlled live-capture module. That module
extracts flow features from real traffic and **reports why they are not compatible with the model**,
so predictions on live traffic are disabled.

| | |
|---|---|
| Model | scikit-learn 1.6.1 `Pipeline` (StandardScaler + OneHotEncoder → RandomForest, 100 trees), SHA-256 pinned |
| Data | *Federated IoT/PC Network Traffic Datasets for FTARL IDS*, Mendeley Data, DOI [10.17632/m8swht7tmn.1](https://data.mendeley.com/datasets/m8swht7tmn/1) (CC BY 4.0), 10,000 labelled rows |
| Verified test metrics | accuracy **0.9355**, attack precision 0.9708, recall 0.8980, F1 0.9330, ROC-AUC 0.9871 (20% held-out split, rule P(attack) ≥ 0.5) — see [docs/MODEL_CARD.md](docs/MODEL_CARD.md) |
| Backend | Python 3.12, FastAPI, SQLAlchemy + SQLite, optional SHAP and Scapy |
| Frontend | React 19, TypeScript, Vite 8, Tailwind CSS 4, Recharts |

> **Read before presenting results:**
> - The test split comes from the same file as the training data, so it is not an independent dataset.
> - The data appears synthetic: one attacker IP, mirrored per-direction counters, constant aggregate features.
> - Real-world performance is unknown. See [docs/MODEL_CARD.md](docs/MODEL_CARD.md) and
>   [docs/LIVE_FEATURE_COMPATIBILITY.md](docs/LIVE_FEATURE_COMPATIBILITY.md).

---

## 1. Prerequisites

- **Python 3.12** in the existing `.venv`, managed with [uv](https://docs.astral.sh/uv/) (0.12 used here).
- **Node.js 22** and npm 10, for the dashboard.
- *Optional, live capture on Windows:* [Npcap](https://npcap.com), installed in "WinPcap API-compatible
  mode". On Linux, capture needs root or `CAP_NET_RAW`/`CAP_NET_ADMIN`. Offline PCAP analysis needs neither.

## 2. Install (into the existing environment)

```powershell
# from the project root; uses the existing .venv — no new environment, nothing installed globally
uv sync --extra explain --extra capture     # core + SHAP explanations + Scapy capture
#   uv sync                                 # core only: tree-path explanations, no PCAP/live capture

cd src/frontend
npm install
cd ../..
```

To use the environment directly instead of through `uv run`, activate it with `.venv\Scripts\Activate.ps1` (PowerShell)
or `source .venv/Scripts/activate` (Git Bash).

## 3. Run

Use two terminals:

```powershell
# 1) backend API on http://127.0.0.1:8000  (OpenAPI docs: http://127.0.0.1:8000/docs)
uv run major-project
#    equivalent: uv run uvicorn major_project.main:app --host 127.0.0.1 --port 8000

# 2) dashboard on http://127.0.0.1:5173  (proxies /api to the backend)
cd src/frontend
npm run dev
```

Open **http://127.0.0.1:5173**. Data is stored in `data/nids.db`, which is git-ignored.

**Demo data.** Export the 2,000 held-out test rows. These are features only, and none were used in
training:

```powershell
uv run python scripts/export_demo_csv.py      # writes data/demo/heldout_test_features.csv (+ labels file)
```

Upload `data/demo/heldout_test_features.csv` on **Analyze**. The result should be 925 Attack and 1,075 Benign,
matching the verified confusion matrix (TN 973, FP 27, FN 102, TP 898).

## 4. Test and lint

```powershell
uv run pytest -q                                   # backend: 220 tests
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts

cd src/frontend
npm run lint        # oxlint
npm run typecheck   # tsc -b
npm test            # 14 unit/component tests (+5 end-to-end tests, skipped unless E2E_BASE_URL is set)
npm run build
```

None of these need administrator rights, a network connection, or a capture device. Packet capture
is replaced with fakes in tests. Tests that need the optional extras skip cleanly without them.

End-to-end test against running servers: start both servers, upload the demo CSV, then run

```bash
E2E_BASE_URL=http://127.0.0.1:5173 npx vitest run src/test/e2e.test.tsx
```

Reproduce the evaluation from the dataset (no retraining):

```powershell
uv run python scripts/reproduce_evaluation.py       # -> src/major_project/evaluation/verified_metrics.json
uv run python scripts/build_training_reference.py   # -> training_reference.json (training split summary)
```

Check packet-capture support on this machine. This opens one socket and closes it without reading packets:

```powershell
uv run --extra capture python -m major_project.services.capture_diagnostics
```

## 5. Using the API

All endpoints are under `/api`; interactive documentation is at `/docs`. Errors look like
`{"error": {"code", "message", "details"}}`.

```bash
# health and model
curl http://127.0.0.1:8000/api/health
curl http://127.0.0.1:8000/api/model/info            # the exact 35-feature schema, classes, threshold, limits
curl http://127.0.0.1:8000/api/model/performance     # verified offline metrics + ROC/PR points

# single prediction (body: exactly the 35 features). Extract the SYNTHETIC example record first:
uv run python -c "import json; print(json.dumps(json.load(open('tests/fixtures/synthetic_flow_record.json'))['record']))" > record.json
curl -X POST http://127.0.0.1:8000/api/predict -H "Content-Type: application/json" --data @record.json
# batch (max 1,000 records): body is {"records": [ {...}, {...} ]}
uv run python -c "import json; r=json.load(open('record.json')); print(json.dumps({'records': [r, r]}))" > batch.json
curl -X POST "http://127.0.0.1:8000/api/predict/batch?explain=alerts" -H "Content-Type: application/json" \
     --data @batch.json

# CSV analysis (max 10 MB / 50,000 rows; whole file validated before anything is stored)
curl -F "file=@data/demo/heldout_test_features.csv" http://127.0.0.1:8000/api/analyze/csv
curl "http://127.0.0.1:8000/api/analyses/<id>/predictions?label=Attack&limit=100"
curl -o results.csv "http://127.0.0.1:8000/api/analyses/<id>/export.csv"

# alerts and dashboard
curl "http://127.0.0.1:8000/api/alerts?severity=high&proto=TCP&limit=50"
curl http://127.0.0.1:8000/api/alerts/1               # features + local explanation
curl http://127.0.0.1:8000/api/dashboard/summary
curl "http://127.0.0.1:8000/api/dashboard/trends?bucket=hour"

# network (no IP/MAC addresses are returned or stored)
curl http://127.0.0.1:8000/api/network/interfaces
curl -F "file=@capture.pcap" http://127.0.0.1:8000/api/network/pcap      # compatibility report, not predictions
curl http://127.0.0.1:8000/api/network/live/status                       # localhost only
curl -X POST http://127.0.0.1:8000/api/network/live/start -H "Content-Type: application/json" \
     -d '{"interface": "Wi-Fi", "authorized": true, "max_duration_seconds": 60}'
curl -X POST http://127.0.0.1:8000/api/network/live/stop
curl -X POST http://127.0.0.1:8000/api/network/live/reset   # clear the finished session; saved runs are kept
```

`tests/fixtures/synthetic_flow_record.json` holds a **synthetic** example record under its `record` key.
It is for trying the API only and is not real traffic.

## 6. Configuration

All settings are optional environment variables (or a `.env` file). See [.env.example](.env.example). Key ones:

| Variable | Default | Meaning |
|---|---|---|
| `NIDS_ATTACK_THRESHOLD` | `0.5` | Label Attack when P(attack) ≥ threshold |
| `NIDS_SEVERITY_HIGH_MIN_PROBABILITY` | `0.8` | Attack alerts at/above this are "high", else "medium" |
| `NIDS_EXPLANATION_METHOD` | `auto` | `shap_tree` if installed, else `tree_path` |
| `NIDS_DATABASE_URL` | `sqlite:///<project>/data/nids.db` | SQLAlchemy URL |
| `NIDS_MAX_UPLOAD_BYTES` / `NIDS_MAX_CSV_ROWS` / `NIDS_MAX_BATCH_RECORDS` | 10 MB / 50,000 / 1,000 | Input limits |
| `NIDS_MAX_PCAP_BYTES` / `NIDS_MAX_PCAP_PACKETS` | 50 MB / 1,000,000 | PCAP limits |
| `NIDS_CAPTURE_TOKEN` | unset | If set, live start/stop need header `X-Capture-Token` |
| `NIDS_LIVE_INFERENCE_ENABLED` | `false` | Has no effect while features are incompatible (the gate also requires compatibility) |

## 7. Security model (local use)

- Both servers bind to **127.0.0.1**.
- **Capture control:** capture-check and live start/stop/status are accepted only from localhost.
  Starting a capture requires an explicit `authorized: true` field and, optionally, a token. The BPF
  filter is restricted to a safe character set, and the duration is capped.
- **CSRF:** state-changing requests that carry a browser `Origin` other than the dashboard's are
  rejected. CORS is limited to the dashboard origin.
- **Uploads:** files are size-checked from `Content-Length` before parsing, and again while reading.
  Row, packet and flow limits apply. Filenames are display-only and sanitised.
- **Model loading:** the SHA-256 hash is pinned, and an allow-list unpickler rejects any non-sklearn/numpy object.
- **Privacy:**
  - No packet payloads, IP or MAC addresses are stored, logged or returned.
  - Logs record the method, path, status and duration only.
  - Errors never include stack traces.

## 8. Project structure

```text
src/major_project/
  model/        trusted model artifact (unchanged)       training/  notebook + dataset (unchanged)
  result/       original evaluation figures (unchanged)  evaluation/ verified metrics, training reference
  api/          FastAPI routes, security, errors          database/  SQLAlchemy models, queries
  schemas/      request/response models                   services/  inference, explanations, CSV, PCAP,
  core/         settings, logging                                    flows, compatibility, capture
src/frontend/   React dashboard                           scripts/   evaluation / reference / demo export
tests/          pytest suite                              docs/      plan, architecture, model card, compatibility
```

## 9. Known limitations

- **Live and PCAP traffic cannot be scored.** 25 of the 35 model inputs cannot be produced from real
  packets with the training data's meaning. Enabling it would require retraining on features
  computed from real flows, which needs the project owner's approval.
- **The evaluation is offline only**, on a held-out split of a single synthetic-looking capture. It
  is not an independent test set.
- **XGBoost, ANN and LSTM figures are as reported by the notebook.** Those models were not saved, so
  they were not re-run.
- **Probabilities and severity are not calibrated.** P(attack) is the fraction of trees voting
  "attack". Severity labels are configurable triage rules, not measured risk.
- **Database schema:** tables are created automatically at startup. Moving to PostgreSQL would need
  a migration tool such as Alembic.
- **Trends** are grouped by processing time, not by the time the traffic was originally captured.
- **Not yet done on this machine:**
  - analysing a real-traffic PCAP;
  - a real live-capture session. Capture availability on Wi-Fi was verified, but no capture was
    started.
- **Browser testing:** the dashboard was verified by component tests and an end-to-end render
  against the running API (jsdom). No manual or automated test was run in a real browser.

## 10. Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, data flow, threading, database schema.
- [docs/MODEL_CARD.md](docs/MODEL_CARD.md): model, data, verified metrics, limitations.
- [docs/LIVE_FEATURE_COMPATIBILITY.md](docs/LIVE_FEATURE_COMPATIBILITY.md): why live inference is disabled.
- [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md): plan and verified status.

Dataset: Ailabouni, Román Gallego, Pérez-Delgado (2025), Mendeley Data, DOI 10.17632/m8swht7tmn.1, CC BY 4.0.
