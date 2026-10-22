"""Checks against the real labelled dataset. Skipped automatically if the CSV is absent."""

import numpy as np
import pytest
from sklearn.model_selection import train_test_split

DROPPED = [
    "attack", "category", "subcategory", "pkSeqID", "stime", "ltime",
    "saddr", "daddr", "seq", "state", "state_number", "Prediction", "Attack Probability (%)",
]  # fmt: skip


@pytest.fixture(scope="module")
def split(dataset):
    y = dataset["attack"].astype(int)
    X = dataset.drop(columns=DROPPED)
    return train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)


def test_service_reproduces_reported_confusion_matrix(service, split):
    _, X_test, _, y_test = split
    preds = service.predict_frame(service.validate_frame(X_test))
    y_pred = np.array([p.label_id for p in preds])
    y_true = y_test.to_numpy()
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    # Matches notebook cell 54 and the saved confusion-matrix figure (threshold P(attack) >= 0.5).
    assert (tn, fp, fn, tp) == (973, 27, 102, 898)


def test_artifact_was_fitted_on_training_split_only(bundle, split):
    X_train = split[0]
    scaler = bundle.pipeline.named_steps["preprocessor"].named_transformers_["numeric"]
    cols = list(scaler.feature_names_in_)
    np.testing.assert_allclose(scaler.mean_, X_train[cols].mean().to_numpy(), rtol=0, atol=1e-9)


def test_real_rows_pass_validation_without_warnings(service, dataset):
    frame = service.validate_frame(dataset.drop(columns=DROPPED).head(500))
    assert all(w == () for w in service.record_warnings(frame))


def test_appended_prediction_column_matches_model(service, dataset):
    """The CSV's 'Prediction' column came from pipeline.predict() (exact 0.5 ties -> Benign)."""
    X = dataset.drop(columns=DROPPED)
    probs = service.attack_probabilities(service.validate_frame(X))
    expected = np.where(probs > 0.5, "Attack", "Benign")
    assert (dataset["Prediction"].to_numpy() == expected).all()
