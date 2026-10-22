import io
import math
import random

import pandas as pd
import pytest

from major_project.services.inference import (
    MAX_REPORTED_ERRORS,
    InferenceService,
    InputValidationError,
)


def _errors(exc_info) -> list[tuple]:
    return [(e.row, e.field, e.message) for e in exc_info.value.errors]


def _fields(exc_info) -> set:
    return {e.field for e in exc_info.value.errors}


# ----------------------------------------------------------------------------- valid inputs


def test_single_prediction_structure(service, synthetic_record):
    [pred] = service.predict_records([synthetic_record])
    assert pred.label in {"Benign", "Attack"}
    assert pred.label_id in {0, 1}
    assert pred.is_attack == (pred.label == "Attack") == (pred.label_id == 1)
    assert 0.0 <= pred.attack_probability <= 1.0
    assert math.isclose(pred.attack_probability + pred.benign_probability, 1.0)
    assert pred.is_attack == (pred.attack_probability >= 0.5)
    assert pred.threshold == 0.5
    assert pred.model_version == service.bundle.model_version
    assert pred.warnings == ()


def test_key_order_does_not_matter(service, synthetic_record):
    keys = list(synthetic_record)
    random.Random(0).shuffle(keys)
    shuffled = {k: synthetic_record[k] for k in keys}
    [a] = service.predict_records([synthetic_record])
    [b] = service.predict_records([shuffled])
    assert a.attack_probability == b.attack_probability


def test_batch_prediction_matches_single(service, synthetic_record):
    other = dict(synthetic_record, pkts=90, spkts=45, dpkts=45, proto="TCP", dport=445)
    batch = service.predict_records([synthetic_record, other])
    assert len(batch) == 2
    assert batch[0] == service.predict_records([synthetic_record])[0]
    assert batch[1] == service.predict_records([other])[0]


def test_integers_and_floats_are_equivalent(service, synthetic_record):
    as_float = {k: float(v) if isinstance(v, int) else v for k, v in synthetic_record.items()}
    assert (
        service.predict_records([synthetic_record])[0].attack_probability
        == service.predict_records([as_float])[0].attack_probability
    )


@pytest.mark.parametrize("threshold, expect_attack", [(0.0, True), (1.0 + 1e-9, None)])
def test_threshold_is_applied(bundle, synthetic_record, threshold, expect_attack):
    if threshold > 1.0:
        with pytest.raises(ValueError):
            InferenceService(bundle, attack_threshold=threshold)
        return
    [pred] = InferenceService(bundle, attack_threshold=threshold).predict_records(
        [synthetic_record]
    )
    assert pred.is_attack is expect_attack and pred.label == "Attack"


def test_warning_for_feature_constant_in_training(service, synthetic_record):
    [pred] = service.predict_records([dict(synthetic_record, TnBPSrcIP=250)])
    assert any("TnBPSrcIP" in w and "no effect" in w for w in pred.warnings)


def test_warning_for_inconsistent_protocol_number(service, synthetic_record):
    [pred] = service.predict_records([dict(synthetic_record, proto="DNS", proto_number=6)])
    assert any("proto_number" in w for w in pred.warnings)


# ----------------------------------------------------------------------------- invalid inputs


def test_empty_input_rejected(service):
    with pytest.raises(InputValidationError):
        service.predict_records([])


def test_missing_feature_rejected(service, synthetic_record):
    del synthetic_record["dur"]
    with pytest.raises(InputValidationError) as exc:
        service.predict_records([synthetic_record])
    assert _errors(exc) == [(0, "dur", "required feature is missing")]


def test_unexpected_feature_rejected(service, synthetic_record):
    synthetic_record["state_number"] = 1  # a known label-leaking column
    with pytest.raises(InputValidationError) as exc:
        service.predict_records([synthetic_record])
    assert _fields(exc) == {"state_number"}


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), None])
def test_non_finite_or_null_numeric_rejected(service, synthetic_record, value):
    synthetic_record["rate"] = value
    with pytest.raises(InputValidationError) as exc:
        service.predict_records([synthetic_record])
    assert _fields(exc) == {"rate"}


@pytest.mark.parametrize("value", ["12", True, [1], {"v": 1}])
def test_non_numeric_types_rejected(service, synthetic_record, value):
    synthetic_record["pkts"] = value
    with pytest.raises(InputValidationError) as exc:
        service.predict_records([synthetic_record])
    assert _errors(exc) == [(0, "pkts", "must be a number")]


@pytest.mark.parametrize("field, value", [("proto", "tcp"), ("proto", "QUIC"), ("flgs", "FIN")])
def test_unknown_category_rejected(service, synthetic_record, field, value):
    synthetic_record[field] = value
    with pytest.raises(InputValidationError) as exc:
        service.predict_records([synthetic_record])
    assert _fields(exc) == {field}


def test_non_string_category_rejected(service, synthetic_record):
    synthetic_record["proto"] = 6
    with pytest.raises(InputValidationError) as exc:
        service.predict_records([synthetic_record])
    assert _errors(exc) == [(0, "proto", "must be a string")]


@pytest.mark.parametrize(
    "field, value", [("bytes", -1), ("dport", 70000), ("sport", 80.5), ("dur", -0.01)]
)
def test_out_of_domain_values_rejected(service, synthetic_record, field, value):
    synthetic_record[field] = value
    with pytest.raises(InputValidationError) as exc:
        service.predict_records([synthetic_record])
    assert _fields(exc) == {field}


def test_non_mapping_record_rejected(service):
    with pytest.raises(InputValidationError) as exc:
        service.predict_records([["not", "a", "record"]])
    assert _errors(exc)[0][0] == 0


def test_errors_report_row_numbers_and_are_capped(service, synthetic_record):
    bad = dict(synthetic_record, pkts=-5)
    records = [synthetic_record, bad] + [dict(bad) for _ in range(MAX_REPORTED_ERRORS + 10)]
    with pytest.raises(InputValidationError) as exc:
        service.predict_records(records)
    assert exc.value.errors[0].row == 1
    assert len(exc.value.errors) == MAX_REPORTED_ERRORS
    assert exc.value.truncated


# ----------------------------------------------------------------------------- CSV-style frames


def _csv(records: list[dict]) -> pd.DataFrame:
    buffer = io.StringIO()
    pd.DataFrame(records).to_csv(buffer, index=False)
    buffer.seek(0)
    return pd.read_csv(buffer)


def test_frame_from_csv_validates_and_predicts(service, synthetic_record):
    frame = service.validate_frame(_csv([synthetic_record, synthetic_record]))
    assert list(frame.columns) == list(service.schema.feature_order)
    preds = service.predict_frame(frame)
    assert len(preds) == 2 and preds[0] == preds[1]


def test_frame_with_shuffled_columns_is_reordered(service, synthetic_record):
    raw = _csv([synthetic_record])
    raw = raw[list(reversed(raw.columns))]
    frame = service.validate_frame(raw)
    assert list(frame.columns) == list(service.schema.feature_order)


def test_frame_bad_cells_reported_with_offset(service, synthetic_record):
    raw = _csv([synthetic_record, synthetic_record, synthetic_record])
    raw["pkts"] = raw["pkts"].astype(object)
    raw.loc[1, "pkts"] = "lots"
    raw.loc[2, "proto"] = "tcp"
    with pytest.raises(InputValidationError) as exc:
        service.validate_frame(raw, row_offset=100)
    assert sorted((r, f) for r, f, _ in _errors(exc)) == [(101, "pkts"), (102, "proto")]


def test_frame_missing_and_extra_columns(service, synthetic_record):
    raw = _csv([synthetic_record]).drop(columns=["sum"]).assign(saddr="192.168.0.1")
    with pytest.raises(InputValidationError) as exc:
        service.validate_frame(raw)
    assert _fields(exc) == {"sum", "saddr"}


def test_frame_empty_cell_reported_as_missing(service, synthetic_record):
    raw = _csv([synthetic_record])
    raw["mean"] = raw["mean"].astype(object)
    raw.loc[0, "mean"] = ""
    with pytest.raises(InputValidationError) as exc:
        service.validate_frame(raw)
    assert _errors(exc) == [(0, "mean", "missing value")]
