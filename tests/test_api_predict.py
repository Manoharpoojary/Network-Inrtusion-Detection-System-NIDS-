import json

import pytest

from tests.api_helpers import api_client, attackish, synthetic_record


@pytest.fixture
def client(tmp_path):
    with api_client(tmp_path) as c:
        yield c


def test_single_prediction_with_local_explanation(client):
    r = client.post("/api/predict", json=synthetic_record())
    assert r.status_code == 200
    body = r.json()
    assert body["label"] in ("Benign", "Attack")
    assert body["attack_probability"] + body["benign_probability"] == pytest.approx(1.0)
    assert body["model_version"].startswith("rf-")
    assert body["processed_at"].endswith(("Z", "+00:00"))
    exp = body["explanation"]
    assert body["explanation_status"] == "included" and exp["scope"] == "local"
    total = exp["base_value"] + sum(c["contribution"] for c in exp["contributions"])
    assert total + exp["other_contribution"] == pytest.approx(body["attack_probability"], abs=1e-9)


def test_single_prediction_without_explanation(client):
    body = client.post("/api/predict", params={"explain": "false"}, json=synthetic_record()).json()
    assert body["explanation"] is None and body["explanation_status"] == "not_requested"


def test_attack_prediction_creates_alert(client):
    body = client.post("/api/predict", json=attackish(synthetic_record())).json()
    assert body["label"] == "Attack" and body["severity"] == "high"
    assert body["alert_id"] is not None
    alert = client.get(f"/api/alerts/{body['alert_id']}").json()
    assert alert["prediction_id"] == body["prediction_id"]
    assert alert["features"]["proto"] == "TCP"


def test_batch_prediction_summary_and_order(client):
    records = [synthetic_record(), attackish(synthetic_record()), synthetic_record()]
    r = client.post("/api/predict/batch", json={"records": records})
    assert r.status_code == 200
    body = r.json()
    assert [p["flow_index"] for p in body["predictions"]] == [0, 1, 2]
    s = body["summary"]
    assert s["total"] == 3 and s["benign"] + s["attack"] == 3
    assert s["alerts"]["medium"] + s["alerts"]["high"] == s["attack"]
    statuses = {p["explanation_status"] for p in body["predictions"] if p["alert_id"]}
    assert statuses <= {"included"}
    assert all(p["explanation"] is None for p in body["predictions"] if not p["alert_id"])


def test_batch_size_limit(tmp_path):
    with api_client(tmp_path, max_batch_records=2) as c:
        r = c.post("/api/predict/batch", json={"records": [synthetic_record()] * 3})
    assert r.status_code == 413 and r.json()["error"]["code"] == "batch_too_large"


def test_batch_explanation_budget_defers_extra(tmp_path):
    with api_client(tmp_path, max_eager_explanations=1) as c:
        body = c.post(
            "/api/predict/batch", json={"records": [attackish(synthetic_record())] * 3}
        ).json()
        assert [p["explanation_status"] for p in body["predictions"]] == [
            "included", "deferred", "deferred",
        ]  # fmt: skip
        # A deferred alert is explained when opened, then cached.
        alert_id = body["predictions"][2]["alert_id"]
        first = c.get(f"/api/alerts/{alert_id}").json()
        assert first["explanation_status"] == "included" and first["explanation"] is not None
        assert c.get(f"/api/alerts/{alert_id}").json()["explanation"] == first["explanation"]


def test_empty_batch_rejected(client):
    r = client.post("/api/predict/batch", json={"records": []})
    assert r.status_code == 422


@pytest.mark.parametrize(
    "mutate, location",
    [
        (lambda r: r.pop("dur"), "dur"),
        (lambda r: r.update(state_number=1), "state_number"),
        (lambda r: r.update(pkts="12"), "pkts"),
        (lambda r: r.update(pkts=True), "pkts"),
        (lambda r: r.update(bytes=-1), "bytes"),
        (lambda r: r.update(dport=70000), "dport"),
        (lambda r: r.update(proto="tcp"), "proto"),
        (lambda r: r.update(rate=None), "rate"),
    ],
)
def test_invalid_records_rejected_with_location(client, mutate, location):
    record = synthetic_record()
    mutate(record)
    r = client.post("/api/predict", json=record)
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "request_validation"
    assert any(d["location"].endswith(location) for d in err["details"])


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_non_finite_json_rejected(client, value):
    raw = json.dumps(dict(synthetic_record(), rate=value))  # emits NaN / Infinity tokens
    assert "NaN" in raw or "Infinity" in raw
    r = client.post("/api/predict", content=raw, headers={"Content-Type": "application/json"})
    assert r.status_code == 422
    assert r.json()["error"]["details"][0]["location"] == "rate"


def test_invalid_records_are_not_persisted(client):
    client.post("/api/predict", json=dict(synthetic_record(), pkts=-1))
    assert client.get("/api/dashboard/summary").json()["total_processed"] == 0
