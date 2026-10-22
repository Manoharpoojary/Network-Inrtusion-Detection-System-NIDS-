import pytest
from sqlalchemy.exc import OperationalError

from tests.api_helpers import api_client, attackish, synthetic_record


@pytest.fixture
def client(tmp_path):
    with api_client(tmp_path) as c:
        yield c


def test_health_ok(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok"
    assert h["model"]["loaded"] and h["model"]["model_version"].startswith("rf-")
    assert h["database"]["ok"]
    assert h["live_inference"]["enabled"] is False
    assert h["explanations"]["method"] in ("shap_tree", "tree_path")


def test_model_info_schema(client, bundle):
    info = client.get("/api/model/info").json()
    assert [f["name"] for f in info["features"]] == list(bundle.schema.feature_order)
    proto = next(f for f in info["features"] if f["name"] == "proto")
    assert proto["kind"] == "categorical" and "MQTT" in proto["allowed_values"]
    assert sum(f["constant_in_training"] for f in info["features"]) == 15
    assert info["class_labels"] == {"0": "Benign", "1": "Attack"}
    caps = info["capabilities"]
    assert caps["calibrated_probabilities"] is False and caps["live_inference"] is False
    assert caps["multiclass_attack_types"] is False
    assert info["artifact_file"].endswith(".joblib") and "/" not in info["artifact_file"]


def test_global_importance_is_labelled_global(client):
    imp = client.get("/api/model/importance").json()
    assert imp["scope"] == "global" and "does not explain any individual prediction" in imp["note"]
    assert imp["features"][0]["feature"] == "spkts"


def test_model_performance_is_verified_and_flagged(client):
    perf = client.get("/api/model/performance").json()
    assert perf["scope"] == "offline_test_set" and perf["matches_loaded_model"]
    cm = perf["verified"]["metrics"]["threshold_ge_0_5"]["confusion_matrix"]
    assert cm == {"tn": 973, "fp": 27, "fn": 102, "tp": 898}
    assert perf["verified"]["methodology"]["independent_test_set"] is False
    statuses = {m["model"]: m["status"] for m in perf["notebook_reported"]["models"]}
    assert statuses["Random Forest"] == "verified"
    assert statuses["LSTM"] == "reported_not_reverified"
    assert len(perf["verified"]["curves"]["roc"]["fpr"]) > 10


def test_model_unavailable_degrades_gracefully(tmp_path):
    with api_client(tmp_path, model_sha256="0" * 64) as c:
        h = c.get("/api/health").json()
        assert h["status"] == "degraded" and not h["model"]["loaded"]
        assert "SHA-256 mismatch" in h["model"]["error"]
        for method, path, kwargs in [
            ("post", "/api/predict", {"json": synthetic_record()}),
            ("post", "/api/predict/batch", {"json": {"records": [synthetic_record()]}}),
            ("post", "/api/analyze/csv", {"files": {"file": ("a.csv", b"x\n1\n", "text/csv")}}),
            ("get", "/api/model/info", {}),
        ]:
            r = getattr(c, method)(path, **kwargs)
            assert r.status_code == 503 and r.json()["error"]["code"] == "model_unavailable"
        # Stored data and offline metrics remain readable.
        assert c.get("/api/alerts").status_code == 200
        assert c.get("/api/dashboard/summary").status_code == 200
        assert c.get("/api/model/performance").json()["matches_loaded_model"] is False


def test_alert_explanation_unavailable_when_model_down(tmp_path):
    with api_client(tmp_path, max_eager_explanations=0) as c:
        alert_id = c.post(
            "/api/predict", params={"explain": "false"}, json=attackish(synthetic_record())
        ).json()["alert_id"]
    with api_client(tmp_path, model_sha256="0" * 64) as c:
        d = c.get(f"/api/alerts/{alert_id}").json()
    assert d["explanation"] is None and d["explanation_status"] == "unavailable"


def test_inference_failure_is_not_reported_as_success(tmp_path):
    with api_client(tmp_path, raise_server_exceptions=False) as c:
        state = c.app.state.nids

        def boom(frame):
            raise RuntimeError("secret internal detail")

        state.inference.predict_frame = boom
        r = c.post("/api/predict", json=synthetic_record())
        assert r.status_code == 500
        assert r.json() == {
            "error": {
                "code": "internal_error",
                "message": "An internal error occurred.",
                "details": None,
            }
        }
        assert "secret" not in r.text and "Traceback" not in r.text
        del state.inference.predict_frame
        assert c.get("/api/dashboard/summary").json()["total_processed"] == 0


def test_database_error_returns_503(tmp_path, monkeypatch):
    from major_project.database import queries

    def broken(*a, **k):
        raise OperationalError("SELECT", {}, Exception("disk I/O error"))

    with api_client(tmp_path) as c:
        monkeypatch.setattr(queries, "summary_counts", broken)
        r = c.get("/api/dashboard/summary")
    assert r.status_code == 503 and r.json()["error"]["code"] == "database_error"
    assert "disk" not in r.text


def test_unknown_route_and_method(client):
    assert client.get("/api/nope").json()["error"]["code"] == "not_found"
    assert client.delete("/api/alerts").status_code == 405


def test_cors_allows_only_configured_origins(client):
    ok = client.options(
        "/api/health",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = client.options(
        "/api/health",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in bad.headers


def test_openapi_documents_endpoints(client):
    paths = client.get("/openapi.json").json()["paths"]
    for p in [
        "/api/health", "/api/model/info", "/api/predict", "/api/predict/batch",
        "/api/analyze/csv", "/api/alerts", "/api/alerts/{alert_id}",
        "/api/dashboard/summary", "/api/dashboard/trends", "/api/model/performance",
    ]:  # fmt: skip
        assert p in paths


def test_logs_do_not_contain_feature_values(tmp_path):
    import io
    import logging

    from major_project.core.logging import JsonFormatter

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("major_project")
    logger.addHandler(handler)
    try:
        with api_client(tmp_path, log_level="INFO") as c:
            c.post("/api/predict", json=dict(synthetic_record(), sport=54321, bytes=98765))
    finally:
        logger.removeHandler(handler)
    out = stream.getvalue()
    assert '"path": "/api/predict"' in out and '"status": 200' in out
    assert "54321" not in out and "98765" not in out
