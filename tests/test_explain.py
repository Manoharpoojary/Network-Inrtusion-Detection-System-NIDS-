import numpy as np
import pytest

from major_project.services import explain as explain_module
from major_project.services.explain import ExplanationService

HAS_SHAP = explain_module._shap_available()


@pytest.fixture(scope="module")
def frames(service, request):
    record = request.getfixturevalue("synthetic_record_module")
    attackish = dict(record, pkts=90, spkts=45, dpkts=45, proto="TCP", dport=445, dur=0.3)
    return service.validate_records([record, attackish])


@pytest.fixture(scope="module")
def synthetic_record_module():
    import json
    from pathlib import Path

    path = Path(__file__).parent / "fixtures" / "synthetic_flow_record.json"
    return json.loads(path.read_text(encoding="utf-8"))["record"]


@pytest.mark.parametrize(
    "method",
    [
        "tree_path",
        pytest.param("shap_tree", marks=pytest.mark.skipif(not HAS_SHAP, reason="no shap")),
    ],
)
def test_explanations_are_additive(bundle, frames, method):
    svc = ExplanationService(bundle, method=method, top_k=35)
    probs = bundle.pipeline.predict_proba(frames)[:, 1]
    for exp, p in zip(svc.explain_frame(frames), probs, strict=True):
        assert exp.method == method and exp.scope == "local"
        total = exp.base_value + sum(c.contribution for c in exp.contributions)
        assert total + exp.other_contribution == pytest.approx(p, abs=1e-9)
        assert exp.attack_probability == pytest.approx(p)
        assert exp.other_contribution == pytest.approx(0.0, abs=1e-12)  # top_k covers all 35


def test_contributions_are_per_input_feature_with_raw_values(bundle, frames):
    svc = ExplanationService(bundle, method="tree_path", top_k=35)
    [exp, _] = svc.explain_frame(frames)
    names = [c.feature for c in exp.contributions]
    assert sorted(names) == sorted(bundle.schema.feature_order)  # one-hot summed back to `proto`
    by_name = {c.feature: c for c in exp.contributions}
    assert by_name["proto"].value == "HTTP"
    assert by_name["pkts"].value == 30.0
    # Features constant in training are never split on, so they contribute nothing.
    for name in bundle.schema.constant_features:
        assert by_name[name].contribution == 0.0


def test_top_k_and_ordering(bundle, frames):
    svc = ExplanationService(bundle, method="tree_path", top_k=5)
    exp = svc.explain_frame(frames)[1]
    assert len(exp.contributions) == 5
    mags = [abs(c.contribution) for c in exp.contributions]
    assert mags == sorted(mags, reverse=True)


def test_auto_falls_back_without_shap(bundle, monkeypatch):
    monkeypatch.setattr(explain_module, "_shap_available", lambda: False)
    assert ExplanationService(bundle, method="auto").method == "tree_path"
    with pytest.raises(RuntimeError, match="shap is not installed"):
        ExplanationService(bundle, method="shap_tree")


@pytest.mark.skipif(not HAS_SHAP, reason="no shap")
def test_auto_prefers_shap_when_installed(bundle):
    assert ExplanationService(bundle, method="auto").method == "shap_tree"


def test_unknown_method_rejected(bundle):
    with pytest.raises(ValueError):
        ExplanationService(bundle, method="lime")


def test_global_importance_is_separate_and_normalised(bundle):
    imp = ExplanationService(bundle).global_importance()
    assert len(imp) == 35
    assert sum(i["importance"] for i in imp) == pytest.approx(1.0)
    assert imp[0]["feature"] == "spkts"
    assert np.all(np.diff([i["importance"] for i in imp]) <= 0)


def test_explanation_dict_carries_disclaimer(bundle, frames):
    d = ExplanationService(bundle, method="tree_path").explain_frame(frames)[0].as_dict()
    assert d["scope"] == "local" and "not whether the flow is actually malicious" in d["disclaimer"]
