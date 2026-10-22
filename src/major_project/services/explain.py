"""Per-prediction explanations and global feature importance for the Random Forest pipeline.

Two local (per-flow) methods are supported:

* ``shap_tree``: SHAP TreeExplainer (path-dependent), used when the optional ``shap`` package is
  installed (``uv sync --extra explain``).
* ``tree_path``: tree-path contributions ("Saabas"). Each split's change in the attack fraction is
  credited to the feature it splits on. No extra dependency.

Both are additive: ``base_value + sum(contributions) == P(attack)`` for the explained row. They
describe how this model arrived at its score. They are not evidence that a flow is malicious.

Global importance (``global_importance``) is the forest's mean impurity decrease. It describes the
model overall and must not be presented as the reason for an individual prediction.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

import numpy as np
import pandas as pd
from scipy import sparse

from major_project.services.model_loader import ATTACK_CLASS, ModelBundle

logger = logging.getLogger(__name__)

ExplanationMethod = Literal["shap_tree", "tree_path"]
METHOD_DESCRIPTIONS: dict[str, str] = {
    "shap_tree": "SHAP TreeExplainer (path-dependent) on the Random Forest",
    "tree_path": "Tree-path contributions (Saabas method) averaged over the 100 trees",
}
DISCLAIMER = (
    "Shows which input values moved this model's attack score up or down relative to its average. "
    "It explains the model's output, not whether the flow is actually malicious."
)


@dataclass(frozen=True)
class FeatureContribution:
    feature: str
    value: float | str
    contribution: float  # change in P(attack) attributed to this input feature


@dataclass(frozen=True)
class Explanation:
    method: str
    base_value: float  # model's average P(attack) over the training data
    attack_probability: float
    contributions: tuple[FeatureContribution, ...]  # top features by |contribution|
    other_contribution: float  # sum of all remaining features
    scope: str = "local"
    disclaimer: str = DISCLAIMER

    def as_dict(self) -> dict:
        return {
            "scope": self.scope,
            "method": self.method,
            "method_description": METHOD_DESCRIPTIONS[self.method],
            "base_value": self.base_value,
            "attack_probability": self.attack_probability,
            "contributions": [
                {"feature": c.feature, "value": c.value, "contribution": c.contribution}
                for c in self.contributions
            ],
            "other_contribution": self.other_contribution,
            "disclaimer": self.disclaimer,
        }


def _shap_available() -> bool:
    try:
        import shap  # noqa: F401
    except Exception:  # ImportError, or a broken optional install
        return False
    return True


class ExplanationService:
    def __init__(self, bundle: ModelBundle, method: str = "auto", top_k: int = 8):
        if method not in {"auto", "shap_tree", "tree_path"}:
            raise ValueError(f"unknown explanation method {method!r}")
        if method == "shap_tree" and not _shap_available():
            raise RuntimeError("explanation method 'shap_tree' requested but shap is not installed")
        self.bundle = bundle
        self.top_k = top_k
        self.method: ExplanationMethod = (
            "shap_tree" if method == "shap_tree" or (method == "auto" and _shap_available())
            else "tree_path"
        )  # fmt: skip
        self._pre = bundle.pipeline.steps[0][1]
        self._rf = bundle.classifier
        self._attack_col = list(self._rf.classes_).index(ATTACK_CLASS)
        self._owner = self._transformed_to_input_index()
        self._shap_explainer = None
        self._path_matrices: list[sparse.csr_matrix] | None = None
        self._path_bias: float | None = None

    # ------------------------------------------------------------------ feature mapping

    def _transformed_to_input_index(self) -> np.ndarray:
        """For each of the 47 transformed columns, the index of the input feature it came from."""
        order = list(self.bundle.schema.feature_order)
        owner = np.full(len(self._pre.get_feature_names_out()), -1)
        for name, transformer, columns in self._pre.transformers_:
            if name == "remainder":
                continue
            block = self._pre.output_indices_[name]
            if hasattr(transformer, "categories_"):
                sizes = [len(c) for c in transformer.categories_]
                cols = np.repeat([order.index(c) for c in columns], sizes)
            else:
                cols = np.array([order.index(c) for c in columns])
            owner[block] = cols
        if (owner < 0).any():
            raise RuntimeError("could not map every transformed feature to an input feature")
        return owner

    def _transform(self, frame: pd.DataFrame) -> np.ndarray:
        z = self._pre.transform(frame)
        return z.toarray() if sparse.issparse(z) else np.asarray(z, dtype=float)

    def _to_input_space(self, transformed: np.ndarray) -> np.ndarray:
        """Sum transformed-feature contributions per original input feature."""
        out = np.zeros((transformed.shape[0], len(self.bundle.schema.feature_order)))
        np.add.at(out.T, self._owner, transformed.T)
        return out

    # ------------------------------------------------------------------ methods

    def _shap_contributions(self, z: np.ndarray) -> tuple[float, np.ndarray]:
        if self._shap_explainer is None:
            import shap

            self._shap_explainer = shap.TreeExplainer(self._rf)
        values = self._shap_explainer.shap_values(z, check_additivity=True)
        if isinstance(values, list):  # older shap: one array per class
            attack = np.asarray(values[self._attack_col])
        else:
            values = np.asarray(values)
            attack = values[..., self._attack_col] if values.ndim == 3 else values
        base = float(np.ravel(self._shap_explainer.expected_value)[self._attack_col])
        return base, attack

    def _build_path_matrices(self) -> None:
        matrices, bias = [], 0.0
        n_features = self._owner.shape[0]
        for est in self._rf.estimators_:
            tree = est.tree_
            value = tree.value[:, 0, :]
            frac = value[:, self._attack_col] / value.sum(axis=1)
            parent = np.full(tree.node_count, -1)
            internal = np.flatnonzero(tree.children_left != -1)
            parent[tree.children_left[internal]] = internal
            parent[tree.children_right[internal]] = internal
            child = np.flatnonzero(parent >= 0)
            m = sparse.csr_matrix(
                (frac[child] - frac[parent[child]], (child, tree.feature[parent[child]])),
                shape=(tree.node_count, n_features),
            )
            matrices.append(m)
            bias += frac[0]
        self._path_matrices = matrices
        self._path_bias = bias / len(self._rf.estimators_)

    def _path_contributions(self, z: np.ndarray) -> tuple[float, np.ndarray]:
        if self._path_matrices is None:
            self._build_path_matrices()
        total = np.zeros((z.shape[0], self._owner.shape[0]))
        for est, m in zip(self._rf.estimators_, self._path_matrices, strict=True):
            total += (est.decision_path(z.astype(np.float32)) @ m).toarray()
        return float(self._path_bias), total / len(self._rf.estimators_)

    # ------------------------------------------------------------------ public API

    def explain_frame(self, frame: pd.DataFrame) -> list[Explanation]:
        """Explain rows of an already validated frame (columns in model order)."""
        if frame.empty:
            return []
        z = self._transform(frame)
        if self.method == "shap_tree":
            base, transformed = self._shap_contributions(z)
        else:
            base, transformed = self._path_contributions(z)
        contrib = self._to_input_space(transformed)
        probs = self._rf.predict_proba(z)[:, self._attack_col]
        names = list(self.bundle.schema.feature_order)
        results = []
        for i in range(len(frame)):
            row = contrib[i]
            order = np.argsort(-np.abs(row), kind="stable")
            top = order[: self.top_k]
            raw = frame.iloc[i]
            results.append(
                Explanation(
                    method=self.method,
                    base_value=base,
                    attack_probability=float(probs[i]),
                    contributions=tuple(
                        FeatureContribution(
                            feature=names[j],
                            value=_plain(raw[names[j]]),
                            contribution=float(row[j]),
                        )
                        for j in top
                    ),
                    other_contribution=float(row[order[self.top_k :]].sum()),
                )
            )
        return results

    def global_importance(self) -> list[dict]:
        """Mean impurity decrease per input feature (one-hot columns summed). Global, not local."""
        imp = np.zeros(len(self.bundle.schema.feature_order))
        np.add.at(imp, self._owner, self._rf.feature_importances_)
        names = self.bundle.schema.feature_order
        order = np.argsort(-imp, kind="stable")
        return [{"feature": names[j], "importance": float(imp[j])} for j in order]


def _plain(value) -> float | str:
    if isinstance(value, str):
        return value
    return float(value)
