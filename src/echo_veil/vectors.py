"""Vector utilities for Echo Veil.

The spec works with 768-dimensional intent and anchor vectors. These helpers
keep that math in one place. Dimensionality is not hard-coded so the library
stays usable with whatever embedding model a deployment chooses; ``DEFAULT_DIM``
documents the value the spec assumes.
"""

from __future__ import annotations

from collections.abc import Iterable

import numpy as np
from numpy.typing import ArrayLike, NDArray

DEFAULT_DIM = 768

Vector = NDArray[np.float64]


def as_vector(
    values: ArrayLike,
    *,
    allow_empty: bool = False,
    copy: bool = False,
    name: str = "vector",
) -> Vector:
    """Coerce input into a finite, 1-D float64 numpy array.

    ``allow_empty`` exists for the internal protected-anchor sentinel. Public
    embedding boundaries should pass ``allow_empty=False``. ``copy=True`` is
    used when state will retain the result so caller mutation cannot silently
    alter stored memory.
    """
    try:
        arr = np.asarray(values, dtype=np.float64)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if arr.ndim != 1:
        raise ValueError(f"expected a 1-D {name}, got shape {arr.shape}")
    if not allow_empty and arr.size == 0:
        raise ValueError(f"{name} must not be empty")
    if not np.all(np.isfinite(arr)):
        raise ValueError(f"{name} must contain only finite values")
    if copy:
        return np.array(arr, dtype=np.float64, copy=True, order="C")
    return arr


def normalize(vec: ArrayLike) -> Vector:
    """Return the unit-length version of ``vec``.

    A zero vector is returned unchanged (its norm is undefined). Callers that
    require a non-zero vector should validate separately.
    """
    arr = as_vector(vec, allow_empty=False)
    norm = float(np.linalg.norm(arr))
    if norm == 0.0:
        return arr
    return arr / norm


def cosine_similarity(a: ArrayLike, b: ArrayLike) -> float:
    """Cosine similarity in the range [-1.0, 1.0].

    Returns 0.0 if either vector has zero magnitude, since similarity is
    undefined there and 0.0 is the neutral ("orthogonal") value. Empty vectors
    are rejected as malformed inputs.
    """
    va = as_vector(a, allow_empty=False, name="left vector")
    vb = as_vector(b, allow_empty=False, name="right vector")
    if va.shape != vb.shape:
        raise ValueError(f"dimension mismatch: {va.shape} vs {vb.shape}")
    na, nb = float(np.linalg.norm(va)), float(np.linalg.norm(vb))
    if na == 0.0 or nb == 0.0:
        return 0.0
    # Floating-point roundoff can produce values a few ulps outside the
    # mathematical cosine range, which then poisons confidence validation.
    return float(np.clip(np.dot(va, vb) / (na * nb), -1.0, 1.0))


def centroid(vectors: Iterable[ArrayLike]) -> Vector:
    """Mean vector of a non-empty iterable of vectors."""
    prepared = [as_vector(v, allow_empty=False) for v in vectors]
    if not prepared:
        raise ValueError("cannot take the centroid of an empty set")
    expected_shape = prepared[0].shape
    for vector in prepared[1:]:
        if vector.shape != expected_shape:
            raise ValueError(
                f"dimension mismatch in centroid: {expected_shape} vs {vector.shape}"
            )
    mat = np.stack(prepared)
    return mat.mean(axis=0)
