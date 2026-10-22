"""Load the trusted Random Forest pipeline safely and describe its input schema.

A joblib file is a pickle, and unpickling can run arbitrary code. Two safeguards apply here:

1. The SHA-256 of the file must match the pinned hash of the trusted artifact.
2. A restricted unpickler only resolves scikit-learn classes, NumPy array/scalar types,
   joblib's array wrapper and the built-in ``slice``. Any other global (``os.system``,
   ``builtins.eval``, functions, ...) aborts the load.

The artifact was saved from Colab, where ``dill`` had patched pickle; that is why it refers to
``dill._dill._load_type("slice")``. That single call is mapped to the built-in ``slice`` type so
``dill`` does not need to be installed.
"""

from __future__ import annotations

import hashlib
import logging
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import sklearn
from joblib.numpy_pickle import NumpyUnpickler
from joblib.numpy_pickle_utils import _validate_fileobject_and_memmap
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import InconsistentVersionWarning
from sklearn.pipeline import Pipeline

logger = logging.getLogger(__name__)

# Verified from the training notebook: y = df["attack"], where 0 = normal and 1 = attack.
CLASS_LABELS: dict[int, str] = {0: "Benign", 1: "Attack"}
ATTACK_CLASS = 1

_EXACT_ALLOWED_GLOBALS = {
    ("numpy", "dtype"),
    ("numpy", "ndarray"),
    ("numpy._core.multiarray", "_reconstruct"),
    ("numpy._core.multiarray", "scalar"),
    ("numpy.core.multiarray", "_reconstruct"),
    ("numpy.core.multiarray", "scalar"),
    ("joblib.numpy_pickle", "NumpyArrayWrapper"),
    ("builtins", "slice"),
}
_DILL_SAFE_TYPES: dict[str, type] = {"slice": slice}


class ModelLoadError(RuntimeError):
    """The model artifact could not be loaded or is not the expected kind of model."""


class ArtifactIntegrityError(ModelLoadError):
    """The artifact's SHA-256 does not match the trusted hash."""


class UnsafeArtifactError(ModelLoadError):
    """The artifact references a Python object outside the allow-list."""


def _dill_load_type(name: str) -> type:
    if name not in _DILL_SAFE_TYPES:
        raise UnsafeArtifactError(f"Blocked dill type reference: {name!r}")
    return _DILL_SAFE_TYPES[name]


class _RestrictedUnpickler(NumpyUnpickler):
    """joblib unpickler that only resolves allow-listed globals.

    joblib >= 1.6 routes nested object-array pickles through this same ``find_class``.
    """

    def find_class(self, module: str, name: str) -> Any:
        if (module, name) == ("dill._dill", "_load_type"):
            return _dill_load_type
        if (module, name) in _EXACT_ALLOWED_GLOBALS:
            return super().find_class(module, name)

        if module == "numpy" or module.startswith("sklearn."):
            obj = super().find_class(module, name)
            if isinstance(obj, type) and issubclass(obj, np.generic):
                return obj  # NumPy scalar types such as numpy.float64
            if module.startswith("sklearn.") and isinstance(obj, type):
                return obj  # scikit-learn classes (estimators, Tree, helper containers)
        raise UnsafeArtifactError(f"Blocked global in model artifact: {module}.{name}")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def restricted_joblib_load(path: Path) -> Any:
    """Equivalent of ``joblib.load(path)`` using the restricted unpickler."""
    with (
        path.open("rb") as raw,
        _validate_fileobject_and_memmap(raw, str(path), None) as (
            fobj,
            _,
        ),
    ):
        if isinstance(fobj, str):
            raise ModelLoadError("Legacy multi-file joblib format is not supported")
        return _RestrictedUnpickler(str(path), fobj, ensure_native_byte_order=True).load()


@dataclass(frozen=True)
class FeatureSchema:
    """The exact input contract of the fitted pipeline."""

    feature_order: tuple[str, ...]
    numeric_features: tuple[str, ...]
    categorical_features: dict[str, tuple[str, ...]]
    # Numeric features whose training variance was zero, with their constant training value.
    # The forest never splits on them, so they cannot influence a prediction.
    constant_features: dict[str, float]


@dataclass(frozen=True)
class ModelBundle:
    pipeline: Pipeline
    schema: FeatureSchema
    sha256: str
    path: Path
    sklearn_version: str
    n_estimators: int
    # Non-empty when the artifact was pickled with a different scikit-learn version.
    version_warnings: tuple[str, ...] = ()
    loaded_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def model_version(self) -> str:
        return f"rf-{self.sha256[:12]}"

    @property
    def classifier(self) -> RandomForestClassifier:
        return self.pipeline.steps[-1][1]


def _extract_schema(pipeline: Pipeline) -> FeatureSchema:
    pre = pipeline.steps[0][1]
    if not isinstance(pre, ColumnTransformer):
        raise ModelLoadError("First pipeline step is not a ColumnTransformer")

    numeric: tuple[str, ...] = ()
    categorical: dict[str, tuple[str, ...]] = {}
    constant: dict[str, float] = {}
    for name, transformer, columns in pre.transformers_:
        if name == "remainder":
            continue
        if hasattr(transformer, "categories_"):
            for column, cats in zip(columns, transformer.categories_, strict=True):
                categorical[column] = tuple(str(c) for c in cats)
        elif hasattr(transformer, "mean_"):
            numeric = tuple(columns)
            for column, mean, var in zip(columns, transformer.mean_, transformer.var_, strict=True):
                if var == 0:
                    constant[column] = float(mean)
        else:
            raise ModelLoadError(f"Unexpected transformer {name!r} in preprocessor")

    order = tuple(str(c) for c in pipeline.feature_names_in_)
    if set(order) != set(numeric) | set(categorical):
        raise ModelLoadError("Pipeline input columns do not match its transformers")
    return FeatureSchema(order, numeric, categorical, constant)


def _validate_pipeline(obj: Any) -> Pipeline:
    if not isinstance(obj, Pipeline):
        raise ModelLoadError(f"Artifact is {type(obj).__name__}, expected a sklearn Pipeline")
    clf = obj.steps[-1][1]
    if not isinstance(clf, RandomForestClassifier):
        raise ModelLoadError(f"Final step is {type(clf).__name__}, expected RandomForestClassifier")
    if list(clf.classes_) != sorted(CLASS_LABELS):
        raise ModelLoadError(f"Unexpected classes {list(clf.classes_)}, expected [0, 1]")
    if not hasattr(obj, "feature_names_in_"):
        raise ModelLoadError("Pipeline was not fitted on a DataFrame; feature names unknown")
    return obj


def load_model(path: Path, expected_sha256: str | None, n_jobs: int | None = 1) -> ModelBundle:
    """Verify, load and describe the model artifact.

    ``n_jobs`` overrides the forest's parallelism in memory only; the file is never modified.
    """
    path = Path(path)
    if not path.is_file():
        raise ModelLoadError(f"Model artifact not found: {path.name}")

    digest = sha256_of(path)
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        raise ArtifactIntegrityError(
            f"SHA-256 mismatch for {path.name}: got {digest}, expected {expected_sha256}"
        )

    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", InconsistentVersionWarning)
            obj = restricted_joblib_load(path)
    except ModelLoadError:
        raise
    except Exception as exc:  # corrupted file, incompatible library versions, ...
        raise ModelLoadError(f"Could not unpickle {path.name}: {type(exc).__name__}") from exc

    pipeline = _validate_pipeline(obj)
    schema = _extract_schema(pipeline)
    clf = pipeline.steps[-1][1]
    if n_jobs is not None:
        clf.n_jobs = n_jobs

    bundle = ModelBundle(
        pipeline=pipeline,
        schema=schema,
        sha256=digest,
        path=path,
        sklearn_version=sklearn.__version__,
        n_estimators=len(clf.estimators_),
        version_warnings=tuple(
            sorted({str(w.message) for w in caught if w.category is InconsistentVersionWarning})
        ),
    )
    for message in bundle.version_warnings:
        logger.warning("model version mismatch: %s", message)
    logger.info(
        "model loaded",
        extra={"model_version": bundle.model_version, "features": len(schema.feature_order)},
    )
    return bundle
