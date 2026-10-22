import csv
import io

import pandas as pd
import pytest
from sklearn.model_selection import train_test_split

from tests.api_helpers import api_client, attackish, csv_bytes, synthetic_record, upload

LABEL_AND_ID_COLUMNS = [
    "attack", "category", "subcategory", "pkSeqID", "stime", "ltime", "saddr", "daddr", "seq",
    "state", "state_number", "Prediction", "Attack Probability (%)",
]  # fmt: skip


@pytest.fixture
def client(tmp_path):
    with api_client(tmp_path) as c:
        yield c


@pytest.fixture(scope="module")
def heldout(dataset):
    """200 rows of the notebook's held-out test split (never seen in training)."""
    y = dataset["attack"]
    _, test = train_test_split(dataset, test_size=0.20, random_state=42, stratify=y)
    return test.head(200)


def test_csv_of_heldout_rows_produces_real_predictions(client, heldout, bundle):
    features = heldout[list(bundle.schema.feature_order)]
    r = upload(client, csv_bytes(features), name="heldout.csv")
    assert r.status_code == 200, r.text
    body = r.json()
    a = body["analysis"]
    assert a["source"] == "csv" and a["status"] == "completed" and a["filename"] == "heldout.csv"
    assert a["total_records"] == 200 == a["benign_count"] + a["attack_count"]
    assert (
        body["summary"]["alerts"]["medium"] + body["summary"]["alerts"]["high"] == a["alert_count"]
    )
    assert len(body["predictions"]) == 100 and body["predictions_truncated"]
    # Same results as calling the pipeline directly with the >= 0.5 rule.
    probs = bundle.pipeline.predict_proba(features)[:, 1]
    page = client.get(body["results_url"], params={"limit": 1000}).json()
    assert page["total"] == 200
    got = [p["attack_probability"] for p in page["items"]]
    assert got == pytest.approx(list(probs))
    assert [p["label"] for p in page["items"]] == [
        "Attack" if p >= 0.5 else "Benign" for p in probs
    ]


def test_dataset_columns_rejected_unless_ignored(client, heldout):
    data = csv_bytes(heldout.head(5))
    r = upload(client, data)
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_columns"
    rejected = {d["field"] for d in r.json()["error"]["details"]}
    assert {"saddr", "daddr", "attack", "state"} <= rejected

    r = upload(client, data, ignore_extra_columns="true")
    assert r.status_code == 200
    analysis = r.json()["analysis"]
    assert set(analysis["ignored_columns"]) == set(LABEL_AND_ID_COLUMNS)
    # Ignored columns (including IP addresses) are not stored or returned anywhere.
    assert "192.168." not in r.text
    export = client.get(r.json()["export_url"]).text
    assert "192.168." not in export


def test_export_csv_filters_and_columns(client):
    rows = [synthetic_record(), attackish(synthetic_record()), synthetic_record()]
    body = upload(client, csv_bytes(rows)).json()
    text = client.get(body["export_url"]).text
    parsed = list(csv.DictReader(io.StringIO(text)))
    assert len(parsed) == 3 and parsed[0]["row_index"] == "0"
    assert "attack_probability" in parsed[0] and "saddr" not in parsed[0]
    only_attacks = client.get(body["export_url"], params={"label": "Attack"}).text
    assert all(r["label"] == "Attack" for r in csv.DictReader(io.StringIO(only_attacks)))


def test_invalid_cells_reject_whole_file_with_line_numbers(client):
    rows = [synthetic_record() for _ in range(4)]
    frame = pd.DataFrame(rows).astype(object)
    frame.loc[2, "pkts"] = "lots"
    frame.loc[3, "proto"] = "QUIC"
    r = upload(client, csv_bytes(frame))
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "invalid_features"
    assert {(d["row"], d["csv_line"], d["field"]) for d in err["details"]} == {
        (2, 4, "pkts"), (3, 5, "proto"),
    }  # fmt: skip
    assert client.get("/api/dashboard/summary").json()["total_processed"] == 0


def test_missing_column_rejected(client):
    frame = pd.DataFrame([synthetic_record()]).drop(columns=["dur"])
    r = upload(client, csv_bytes(frame))
    assert r.status_code == 422
    assert r.json()["error"]["details"] == [
        {"row": None, "field": "dur", "message": "required feature is missing"}
    ]


def test_duplicate_column_rejected(client):
    text = csv_bytes([synthetic_record()]).decode()
    header, row = text.splitlines()
    data = f"{header},pkts\n{row},30\n".encode()
    r = upload(client, data)
    assert r.status_code == 422 and r.json()["error"]["details"][0]["field"] == "pkts"


@pytest.mark.parametrize(
    "data, code, status",
    [
        (b"", "empty_file", 400),
        (b"   \n", "empty_file", 400),
        (b"flgs,proto\n", "empty_file", 400),
        ("caf\xe9".encode("latin-1"), "invalid_encoding", 400),
    ],
)
def test_malformed_files(client, data, code, status):
    r = upload(client, data)
    assert r.status_code == status and r.json()["error"]["code"] == code


def test_upload_size_limit(tmp_path):
    with api_client(tmp_path, max_upload_bytes=2048) as c:
        data = csv_bytes([synthetic_record()] * 50)
        assert len(data) > 2048
        r = upload(c, data)
    assert r.status_code == 413 and r.json()["error"]["code"] == "upload_too_large"


def test_row_limit(tmp_path):
    with api_client(tmp_path, max_csv_rows=3) as c:
        r = upload(c, csv_bytes([synthetic_record()] * 4))
    assert r.status_code == 413 and r.json()["error"]["code"] == "too_many_rows"


def test_chunked_processing_spans_chunks(tmp_path):
    with api_client(tmp_path, csv_chunk_rows=2) as c:
        rows = [synthetic_record(), attackish(synthetic_record())] * 3
        body = upload(c, csv_bytes(rows)).json()
        page = c.get(body["results_url"]).json()
    assert [p["row_index"] for p in page["items"]] == list(range(6))
    assert [p["label"] for p in page["items"]] == ["Benign", "Attack"] * 3


def test_filename_is_sanitised(client):
    r = upload(client, csv_bytes([synthetic_record()]), name="../../etc/passwd<script>.csv")
    assert r.status_code == 200
    assert r.json()["analysis"]["filename"] == "passwd_script_.csv"


def test_results_filter_and_unknown_analysis(client):
    body = upload(client, csv_bytes([synthetic_record(), attackish(synthetic_record())])).json()
    attacks = client.get(body["results_url"], params={"label": "Attack"}).json()
    assert attacks["total"] == 1 and attacks["items"][0]["row_index"] == 1
    assert client.get("/api/analyses/does-not-exist").status_code == 404
    assert client.get("/api/analyses/does-not-exist/export.csv").status_code == 404
    listing = client.get("/api/analyses").json()
    assert listing["total"] == 1 and listing["items"][0]["id"] == body["analysis"]["id"]
