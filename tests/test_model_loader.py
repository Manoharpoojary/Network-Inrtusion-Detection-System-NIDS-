import os

import joblib
import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from major_project.core.config import DEFAULT_MODEL_PATH, DEFAULT_MODEL_SHA256
from major_project.services.model_loader import (
    CLASS_LABELS,
    ArtifactIntegrityError,
    ModelLoadError,
    UnsafeArtifactError,
    load_model,
    restricted_joblib_load,
)

EXPECTED_FEATURE_ORDER = [
    "flgs", "flgs_number", "proto", "proto_number", "sport", "dport", "pkts", "bytes", "dur",
    "mean", "stddev", "sum", "min", "max", "spkts", "dpkts", "sbytes", "dbytes", "rate", "srate",
    "drate", "TnBPSrcIP", "TnBPDstIP", "TnP_PSrcIP", "TnP_PDstIP", "TnP_PerProto",
    "TnP_Per_Dport", "AR_P_Proto_P_SrcIP", "AR_P_Proto_P_DstIP", "N_IN_Conn_P_DstIP",
    "N_IN_Conn_P_SrcIP", "AR_P_Proto_P_Sport", "AR_P_Proto_P_Dport",
    "Pkts_P_State_P_Protocol_P_DestIP", "Pkts_P_State_P_Protocol_P_SrcIP",
]  # fmt: skip
CONSTANT_IN_TRAINING = {
    "flgs_number", "TnBPSrcIP", "TnBPDstIP", "TnP_PSrcIP", "TnP_PDstIP", "TnP_PerProto",
    "TnP_Per_Dport", "AR_P_Proto_P_SrcIP", "AR_P_Proto_P_DstIP", "N_IN_Conn_P_DstIP",
    "N_IN_Conn_P_SrcIP", "AR_P_Proto_P_Sport", "AR_P_Proto_P_Dport",
    "Pkts_P_State_P_Protocol_P_DestIP", "Pkts_P_State_P_Protocol_P_SrcIP",
}  # fmt: skip


def test_trusted_artifact_loads(bundle):
    assert isinstance(bundle.pipeline, Pipeline)
    assert isinstance(bundle.classifier, RandomForestClassifier)
    assert bundle.sha256 == DEFAULT_MODEL_SHA256
    assert bundle.n_estimators == 100
    assert bundle.model_version == "rf-" + DEFAULT_MODEL_SHA256[:12]
    assert bundle.version_warnings == ()
    assert hasattr(bundle.pipeline, "predict_proba")


def test_feature_schema_and_order(bundle):
    schema = bundle.schema
    assert list(schema.feature_order) == EXPECTED_FEATURE_ORDER
    assert schema.categorical_features == {
        "flgs": ("PA", "S", "U"),
        "proto": (
            "CoAP", "DNS", "HTTP", "HTTPS", "ICMP", "MQTT", "NTP", "RTSP", "SMB", "SSDP", "TCP",
        ),
    }  # fmt: skip
    assert set(schema.numeric_features) == set(EXPECTED_FEATURE_ORDER) - {"flgs", "proto"}
    assert set(schema.constant_features) == CONSTANT_IN_TRAINING
    assert all(v == 1.0 for v in schema.constant_features.values())


def test_class_label_mapping(bundle):
    assert list(bundle.classifier.classes_) == [0, 1]
    assert CLASS_LABELS == {0: "Benign", 1: "Attack"}


def test_n_jobs_override_does_not_change_predictions(bundle, synthetic_record):
    import pandas as pd

    frame = pd.DataFrame([synthetic_record])[EXPECTED_FEATURE_ORDER]
    parallel = load_model(DEFAULT_MODEL_PATH, DEFAULT_MODEL_SHA256, n_jobs=-1)
    assert bundle.classifier.n_jobs == 1
    np.testing.assert_array_equal(
        bundle.pipeline.predict_proba(frame), parallel.pipeline.predict_proba(frame)
    )


def test_hash_mismatch_is_refused():
    with pytest.raises(ArtifactIntegrityError):
        load_model(DEFAULT_MODEL_PATH, "0" * 64)


def test_missing_artifact(tmp_path):
    with pytest.raises(ModelLoadError, match="not found"):
        load_model(tmp_path / "absent.joblib", None)


def test_corrupt_artifact(tmp_path):
    path = tmp_path / "corrupt.joblib"
    path.write_bytes(b"\x80\x04 not really a pickle")
    with pytest.raises(ModelLoadError):
        load_model(path, None)


class _Exploit:
    """Unpickling this would call os.getcwd(): stands in for an arbitrary-code payload."""

    def __reduce__(self):
        return (os.getcwd, ())


def test_malicious_global_is_blocked(tmp_path):
    path = tmp_path / "evil.joblib"
    joblib.dump({"payload": _Exploit()}, path)
    with pytest.raises(UnsafeArtifactError, match="os|nt|posix"):
        restricted_joblib_load(path)


def test_malicious_global_inside_object_array_is_blocked(tmp_path):
    # joblib stores object arrays as a nested pickle stream; it must use the same allow-list.
    path = tmp_path / "evil_array.joblib"
    joblib.dump(np.array([_Exploit()], dtype=object), path)
    with pytest.raises(UnsafeArtifactError):
        restricted_joblib_load(path)


def test_non_pipeline_artifact_is_rejected(tmp_path):
    path = tmp_path / "scaler.joblib"
    joblib.dump(StandardScaler().fit(np.arange(6.0).reshape(-1, 1)), path)
    with pytest.raises(ModelLoadError, match="expected a sklearn Pipeline"):
        load_model(path, None)
