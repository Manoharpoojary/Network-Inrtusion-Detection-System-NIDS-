from datetime import UTC, datetime, timedelta

import pytest

from tests.api_helpers import api_client, attackish, csv_bytes, synthetic_record, upload


@pytest.fixture
def client(tmp_path):
    with api_client(tmp_path) as c:
        yield c


def test_empty_dashboard(client):
    s = client.get("/api/dashboard/summary").json()
    assert s["total_processed"] == 0 and s["attack_share"] is None
    assert s["alerts"]["total"] == 0 and s["recent_alerts"] == []
    assert "not a measure of model accuracy" in s["scope"]


def test_summary_counts_match_inputs(client):
    client.post("/api/predict", json=synthetic_record())
    client.post("/api/predict/batch", json={"records": [attackish(synthetic_record())] * 2})
    upload(client, csv_bytes([synthetic_record(), attackish(synthetic_record())]))
    s = client.get("/api/dashboard/summary").json()
    assert s["total_processed"] == 5
    assert s["attack"] == 3 and s["benign"] == 2
    assert s["attack_share"] == pytest.approx(0.6)
    assert s["alerts"]["total"] == 3 == s["alerts"]["open"]
    assert s["by_source"] == {"api_single": 1, "api_batch": 2, "csv": 2}
    assert s["analyses"] == 3
    assert len(s["recent_alerts"]) == 3
    assert s["recent_alerts"][0]["source"] == "csv"  # newest first


def test_alert_list_filters_search_and_pagination(client):
    client.post(
        "/api/predict/batch",
        json={"records": [attackish(synthetic_record())] * 3 + [synthetic_record()]},
    )
    all_alerts = client.get("/api/alerts").json()
    assert all_alerts["total"] == 3
    assert all(a["severity"] in ("medium", "high") for a in all_alerts["items"])
    page = client.get("/api/alerts", params={"limit": 2, "offset": 2}).json()
    assert page["total"] == 3 and len(page["items"]) == 1
    assert client.get("/api/alerts", params={"proto": "TCP"}).json()["total"] == 3
    assert client.get("/api/alerts", params={"proto": "DNS"}).json()["total"] == 0
    assert client.get("/api/alerts", params={"q": "445"}).json()["total"] == 3
    assert client.get("/api/alerts", params={"q": "tc"}).json()["total"] == 3
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert client.get("/api/alerts", params={"since": future}).json()["total"] == 0
    assert client.get("/api/alerts", params={"severity": "critical"}).status_code == 422
    assert client.get("/api/alerts", params={"limit": 500}).status_code == 422


def test_severity_rules_are_configurable(tmp_path):
    # threshold 0 -> every flow is labelled Attack; high only at P(attack) >= 1.
    with api_client(tmp_path, attack_threshold=0.0, severity_high_min_probability=1.0) as c:
        body = c.post("/api/predict", json=synthetic_record()).json()
        assert 0 < body["attack_probability"] < 1
        assert body["label"] == "Attack" and body["severity"] == "medium"
        assert body["alert_id"] is not None
        info = c.get("/api/model/info").json()
        assert ">= 1" in info["severity_rules"]["high"] and info["threshold"] == 0.0


def test_invalid_severity_configuration_rejected():
    from pydantic import ValidationError

    from major_project.core.config import Settings

    with pytest.raises(ValidationError):
        Settings(attack_threshold=0.7, severity_high_min_probability=0.6)


def test_alert_detail_and_missing_alert(client):
    body = client.post("/api/predict", json=attackish(synthetic_record())).json()
    detail = client.get(f"/api/alerts/{body['alert_id']}").json()
    assert detail["features"]["dport"] == 445
    assert detail["explanation"]["scope"] == "local"
    assert detail["status"] == "open" and detail["source"] == "api_single"
    missing = client.get("/api/alerts/999999")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"


def test_trends_bucket_counts(client):
    client.post(
        "/api/predict/batch", json={"records": [synthetic_record(), attackish(synthetic_record())]}
    )
    t = client.get("/api/dashboard/trends", params={"bucket": "hour"}).json()
    assert t["bucket"] == "hour" and len(t["points"]) in (24, 25)
    assert sum(p["benign"] for p in t["points"]) == 1
    assert sum(p["attack"] for p in t["points"]) == 1
    assert sum(p["alerts_high"] + p["alerts_medium"] for p in t["points"]) == 1
    d = client.get("/api/dashboard/trends", params={"bucket": "day"}).json()
    assert sum(p["attack"] for p in d["points"]) == 1


def test_trends_invalid_ranges(client):
    now = datetime.now(UTC)
    r = client.get(
        "/api/dashboard/trends",
        params={"since": now.isoformat(), "until": (now - timedelta(hours=1)).isoformat()},
    )
    assert r.status_code == 422
    r = client.get(
        "/api/dashboard/trends",
        params={"bucket": "hour", "since": (now - timedelta(days=60)).isoformat()},
    )
    assert r.status_code == 422 and "buckets" in r.json()["error"]["message"]


def test_data_persists_across_restarts(tmp_path):
    with api_client(tmp_path) as c:
        alert_id = c.post("/api/predict", json=attackish(synthetic_record())).json()["alert_id"]
    with api_client(tmp_path) as c:
        assert c.get("/api/dashboard/summary").json()["total_processed"] == 1
        assert c.get(f"/api/alerts/{alert_id}").status_code == 200
