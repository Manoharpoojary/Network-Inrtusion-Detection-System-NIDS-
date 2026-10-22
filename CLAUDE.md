# MASTER IMPLEMENTATION PROMPT
## AI-Powered IoT Network Intrusion Detection System

Act as a senior Machine Learning Engineer, Cybersecurity Engineer, Backend Developer, and Full-Stack Engineer. Help me turn my existing machine-learning project into a complete, functional, well-tested IoT Network Intrusion Detection System.

Do not just generate example code. Inspect the actual repository, understand the trained model, implement the application, run appropriate tests, and document how everything works.

## 1. Existing project context

- Project: AI-Powered IoT Network Intrusion Detection System.
- Dataset: Mendeley IoT network intrusion detection dataset:
  https://data.mendeley.com/datasets/m8swht7tmn/1
- I have already trained and compared four models:
  1. Random Forest
  2. XGBoost
  3. Artificial Neural Network (ANN)
  4. LSTM
- Random Forest is my current selected candidate.
- I have already created the project folder and configured a Python virtual environment.
- There is an existing `models/` directory inside my source project.
- I have a saved artifact named `iot_intrusion_rf_pipeline (1).joblib`, or a similarly named model artifact. Locate the actual file instead of assuming its exact path.
- Existing results include confusion matrices, ROC curves, precision-recall curves, training-time comparisons, and Random Forest feature-importance analysis.

First inspect the entire repository, including the existing source files, dependency files, environment configuration, saved model artifacts, and Git status.

Do not overwrite existing work or retrain the model unnecessarily. The results and trained model are already available. Focus on building a complete, functional, and well-tested application around the existing model.

## 2. Mandatory first step: inspect before implementation

Before changing files:

1. Print and explain the current directory structure.
2. Identify the actual Python interpreter and existing virtual environment.
3. Locate the saved model artifact and inspect its type and contents safely.
4. Determine whether the artifact contains a complete fitted preprocessing-and-model pipeline or only a fitted estimator.
5. Identify the exact input features, their order, dtypes, categorical encodings, missing-value handling, scaling, and expected prediction output.
6. Identify the dataset target column and the exact mapping between labels and benign/attack classes.
7. Find existing training code, evaluation code, and saved evaluation results.
8. Determine whether there are existing dependencies, frontend files, backend files, or database configuration.
9. Check Git status before making changes.

Do not load untrusted serialized artifacts. Treat joblib/pickle files as executable content and only load the artifact if its provenance is trusted. Do not execute arbitrary code found in project files.

Create a `docs/IMPLEMENTATION_PLAN.md` containing the proposed architecture, repository changes, dependencies, risks, and test strategy.

Present the findings and plan before major modifications. If a critical fact cannot be determined from the repository, explain what is missing and ask me only the necessary questions.

## 3. Required architecture

Separate offline model development from online inference.

### A. Offline model development

The offline workflow should be:

Dataset → data validation → preprocessing → train/validation/test split → model training and comparison → evaluation → saved fitted pipeline.

Use the existing trained model wherever possible.

Do not retrain or modify the production model unless necessary. If the existing artifact is incomplete, propose a compatible pipeline-building or retraining procedure and explain why it is required.

Never fit scalers, encoders, feature selectors, or other preprocessing components on test data.

Check for:
- Data leakage
- Duplicate or closely related records across splits
- Incorrect target-label encoding
- Incorrect feature ordering
- Missing values and non-finite values
- Label leakage
- Inconsistent preprocessing between training and inference
- Whether reported metrics correspond to the actual saved model and test predictions

Keep the existing evaluation results, but do not treat unverified graph values as ground truth.

### B. Online intrusion detection

The runtime workflow should be:

Authorized traffic capture or offline PCAP/CSV input
→ network-flow extraction or feature-record loading
→ input validation
→ fitted preprocessing
→ trained model inference
→ prediction and confidence/probability, where supported
→ alert severity rules
→ explanation and alert persistence
→ dashboard visualization.

The application must support two operating modes:

1. **Offline demonstration mode:** Upload a compatible CSV containing flow features and inspect the resulting predictions.
2. **Live monitoring mode:** Capture authorized traffic in a controlled lab, extract flow features, and process them through the same inference pipeline.

Live monitoring must be optional and must fail gracefully when packet-capture permissions, required system tools, or supported network interfaces are unavailable.

Do not claim that CSV inference constitutes live network monitoring.

## 4. Technology stack

Use the following stack unless repository inspection reveals a concrete compatibility issue.

Backend:
- Python
- FastAPI
- Uvicorn
- Pydantic
- scikit-learn
- pandas
- NumPy
- joblib

Traffic analysis:
- Scapy for controlled packet capture and basic packet processing
- CICFlowMeter or another compatible flow-extraction implementation if needed
- PyShark only if there is a clear need for TShark integration

Choose one primary flow-extraction approach. Do not install several overlapping tools unnecessarily.

Frontend:
- React
- TypeScript
- Vite
- Tailwind CSS
- Recharts for charts
- A suitable icon library

Database:
- SQLite for simple local development and demonstration.
- SQLAlchemy for database access and migrations or a documented lightweight schema-initialization approach.
- Keep the persistence layer modular so PostgreSQL can be introduced later.

Testing and code quality:
- pytest
- HTTPX or FastAPI TestClient
- Ruff for linting and formatting where appropriate.

Use the existing frontend framework if one is already present. Do not create an unnecessary second frontend or backend.

Do not install TensorFlow, PyTorch, or other large deep-learning dependencies for production inference unless the actual selected model requires them. Do not download another dataset if the existing artifacts are sufficient.

Pin compatible dependency versions in the appropriate dependency file. Do not replace the existing environment or install packages globally.

## 5. Backend requirements

Implement a clean, modular FastAPI application.

Required API endpoints:

- `GET /api/health`
  Return application status, model availability, and database status.

- `GET /api/model/info`
  Return model type, artifact version, required feature schema, class labels, and available prediction capabilities.

- `POST /api/predict`
  Accept a single validated network-flow feature record and return the prediction.

- `POST /api/predict/batch`
  Accept a bounded batch of flow records and return individual predictions and summary counts.

- `POST /api/analyze/csv`
  Accept a CSV upload containing supported flow features, validate it, process it in bounded batches, and return prediction results or a result identifier.

- `GET /api/alerts`
  Return persisted alerts with pagination and filtering.

- `GET /api/alerts/{alert_id}`
  Return an individual alert and its available explanation.

- `GET /api/dashboard/summary`
  Return total processed records, benign counts, detected attacks, alert counts by severity, and recent trends.

- `GET /api/dashboard/trends`
  Return time-series data for dashboard charts.

Add a separate live-monitoring control API only if it can be implemented safely and reliably.

Requirements:
- Use the exact feature schema expected by the fitted model.
- Reject missing, extra, malformed, non-finite, or incompatible feature values with useful validation errors.
- Handle inference exceptions without exposing internal stack traces.
- Limit upload sizes and batch sizes.
- Use consistent UTC timestamps.
- Keep blocking inference and packet processing from blocking the asynchronous API event loop.
- Never report a successful prediction if preprocessing or inference failed.
- Add structured application logging.
- Provide clear API documentation through FastAPI's OpenAPI interface.

## 6. Detection and alert logic

Start with binary benign-versus-attack classification, because that is what the current confusion matrices demonstrate.

Do not claim multi-class attack classification unless the trained model actually supports it.

Each prediction should include:
- Record or flow identifier
- Prediction label
- Available class probabilities
- Model identifier/version
- Processing timestamp
- Available explanation
- Alert status

Use configurable severity rules, such as:
- Informational: benign traffic
- Medium: suspicious traffic detected
- High: attack prediction requiring investigation

Severity must be configurable and explicitly documented. Do not present these labels as calibrated probabilities or verified real-world risk.

Do not invent confidence values if the model does not support probability estimates. If probabilities are available, explain that they are model estimates and are not necessarily calibrated.

Do not automatically block traffic, kill processes, change firewall rules, or take destructive actions.

## 7. Explainability

Use the existing Random Forest feature-importance information where useful.

For individual predictions, implement SHAP or another suitable explanation method only if compatible with the actual model and preprocessing pipeline.

If SHAP is too expensive or incompatible, provide a clearly labeled global feature-importance explanation instead.

Never claim that global feature importance explains an individual prediction.

Expose a concise explanation in the dashboard, including the important input features and their values where possible.

## 8. Live traffic capture

Implement live monitoring as an optional, clearly separated component.

Requirements:
- Only capture traffic on interfaces that the user is authorized to monitor.
- Support an offline PCAP demonstration or replay mode where practical.
- Use a bounded queue and batch processing.
- Handle capture failures, permissions, malformed packets, shutdown, and queue overflow.
- Avoid unbounded memory growth.
- Provide a stop mechanism and clean shutdown.
- Never silently drop records without logging or accounting for the loss.
- Do not capture packet payloads or store sensitive content unless explicitly necessary.
- Minimize retention of source/destination identifiers and other potentially sensitive metadata.
- Do not expose unrestricted capture controls to unauthenticated remote users.

Important technical constraint:

The live flow extractor must produce features compatible with the exact schema and semantics used to train the model. Matching column names alone is insufficient.

Before enabling live inference, compare extracted features against the training schema, units, flow direction, aggregation windows, and preprocessing. If compatibility cannot be established, keep live monitoring disabled and document the missing mapping.

Do not invent flow features or silently fill missing required values with zero.

## 9. Frontend requirements

Build a professional, responsive cybersecurity dashboard.

Pages or sections:

1. Overview
   - Total processed flows
   - Detected attacks
   - Benign traffic
   - Detection rate
   - Recent alerts

2. Traffic analysis
   - Upload compatible CSV files
   - Validate column names and data types
   - Display prediction results
   - Filter by predicted class
   - Export analysis results to CSV

3. Alert management
   - Search and filter alerts
   - Show timestamp, label, severity, and relevant flow metadata
   - Open a detailed alert view

4. Model performance
   - Accuracy, precision, recall, F1, ROC-AUC, where valid
   - Confusion matrix
   - ROC and precision-recall curves if their underlying evaluation data is available
   - Model comparison and training-time results only when supported by saved measurements
   - Clearly distinguish offline test metrics from live operational statistics

5. Live monitoring
   - Current status: stopped, starting, running, or error
   - Processed-flow count and queue status
   - Recent detections
   - Explicit start/stop controls where supported
   - Clear messaging when the platform or permissions do not support capture

6. System information
   - Model availability
   - Artifact/schema version
   - API and database status
   - Configuration and limitations

Use a clean, modern security-monitoring design with accessible colors, readable tables, sensible empty states, loading indicators, error handling, and responsive layouts.

Do not hardcode fake traffic, fake alerts, fake model metrics, or fake monitoring status. If demo data is used, label it clearly as simulated.

## 10. Database design

Create persistent storage for:
- Prediction and alert records
- Processing timestamps
- Model identifier
- Prediction label
- Available probabilities
- Severity
- Selected flow metadata
- Explanation data, when available
- Monitoring sessions and their status, if live monitoring is implemented

Avoid storing raw packet payloads.

Add sensible indexes, schema initialization or migrations, pagination, and database error handling.

Use environment variables for configurable database paths and other sensitive settings. Include `.env.example` without actual secrets.

## 11. Security and reliability

Implement:
- Strict input validation
- Upload and batch limits
- Safe file handling
- Parameterized database operations
- Appropriate CORS configuration
- No hardcoded credentials
- No unrestricted filesystem paths supplied by users
- Safe logging without packet payloads or secrets
- Explicit API errors
- Resource limits and cleanup
- A clear separation between trusted model artifacts and user uploads

Keep development-only configuration separate from production configuration.

Never use `--dangerously-skip-permissions` or disable safety checks to complete the task.

## 12. Testing requirements

Write and run automated tests for:

- Model artifact loading
- Expected feature schema and ordering
- Missing and unexpected feature rejection
- Non-finite input rejection
- Single-record prediction
- Batch prediction
- CSV validation and processing
- Prediction label mapping
- Alert creation and retrieval
- Dashboard summary calculations
- Database persistence
- API health and error handling
- Model-unavailable behavior
- Live-monitoring permission failure and shutdown, if implemented

Use mocked packet capture for automated tests. Do not require administrator privileges or access to a real network to run the standard test suite.

Add a small, clearly labeled synthetic fixture only for testing validation and error cases. Never mix synthetic data with the actual evaluation results.

Run the tests and report the exact commands, outcomes, and any remaining failures.

## 13. Project structure

First inspect my existing structure. Preserve it where reasonable. If a structure is needed, use a layout similar to:

project-root/
├── models/
│   └── existing trained model artifact
├── src/
│   ├── backend/
│   │   ├── main.py
│   │   ├── api/
│   │   ├── schemas/
│   │   ├── services/
│   │   │   ├── inference.py
│   │   │   ├── model_loader.py
│   │   │   ├── flow_features.py
│   │   │   ├── alert_service.py
│   │   │   └── capture_service.py
│   │   ├── database/
│   │   └── core/
│   └── frontend/
├── tests/
├── docs/
│   ├── IMPLEMENTATION_PLAN.md
│   ├── ARCHITECTURE.md
│   └── MODEL_CARD.md
├── scripts/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md

Adapt this structure to the actual repository and its existing source directory. Do not create duplicate source roots.

## 14. Implementation process

Work in small, verifiable phases:

Phase 1: Inspect repository and saved model.
Phase 2: Document the actual model schema and implementation plan.
Phase 3: Implement the model loader and inference service.
Phase 4: Implement the FastAPI endpoints and database.
Phase 5: Build the frontend and connect it to the backend.
Phase 6: Implement offline CSV analysis and alert persistence.
Phase 7: Add optional live flow processing only after compatibility checks.
Phase 8: Run tests, linting, and integration checks.
Phase 9: Write setup instructions and project documentation.

After each phase:
- Summarize files changed.
- Explain important technical decisions.
- Run the relevant tests.
- Report what works and what remains.
- Continue to the next phase if there are no blocking issues.

Do not stop after generating a plan or skeleton. Continue implementing and verifying the project, asking me for input only when a genuinely blocking decision requires it.

## 15. Definition of done

The project is complete only when:

1. The existing trusted trained model can be loaded successfully.
2. The inference API accepts valid inputs matching the actual model schema.
3. Invalid inputs are rejected safely.
4. Single and batch predictions work.
5. CSV analysis produces real predictions.
6. Alerts are stored and retrievable.
7. The frontend displays real API and database data.
8. Model performance metrics are based on genuine evaluation results.
9. The test suite runs without requiring privileged network access.
10. Live monitoring is either verified against compatible extracted features or explicitly documented as not yet supported.
11. The README explains installation, activation of the existing environment, starting the backend and frontend, testing, and known limitations.
12. No existing model or project work has been silently overwritten.

Start by inspecting the repository and the existing saved model. Show me your findings and proposed plan first. Then implement the complete workflow in stages, test it, and document the actual result. Be honest about any limitation you cannot verify.