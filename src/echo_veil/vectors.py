"""Vector utilities for Echo Veil.

The spec works with 768-dimensional intent and anchor vectors. These helpers
keep that math in one place. Dimensionality is not hard-coded so the library
stays usable with whatever embedding model a deployment chooses; ``DEFAULT_DIM``
documents the value the spec assumes.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

DEFAULT_DIM = 768

Vector = NDArray[np.float64]


def as_vector(values) -> Vector:
    """Coerce input into a 1-D float64 numpy array."""
    arr = np.asarray(values, dtype=np.float64)
    if arr.ndim != 1:
        raise ValueError(f"expected a 1-D vector, got shape {arr.shape}")
    return arr


def normalize(vec) -> Vector:
    """Return the unit-length version of ``vec``.

    A zero vector is returned unchanged (its norm is undefined). Callers that
    require a non-zero vector should validate separately.
    """
    arr = as_vector(vec)
    norm = float(np.linalg.norm(arr))
    if norm == 0.0:
        return arr
    return arr / norm


def cosine_similarity(a, b) -> float:
    """Cosine similarity in the range [-1.0, 1.0].

    Returns 0.0 if either vector is zero-length, since similarity is undefined
    there and 0.0 is the neutral ("orthogonal") value.
    """
    va, vb = as_vector(a), as_vector(b)
    if va.shape != vb.shape:
        raise ValueError(f"dimension mismatch: {va.shape} vs {vb.shape}")
    na, nb = float(np.linalg.norm(va)), float(np.linalg.norm(vb))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return float(np.dot(va, vb) / (na * nb))


def centroid(vectors) -> Vector:
    """Mean vector of a non-empty iterable of vectors."""
    mat = np.asarray([as_vector(v) for v in vectors], dtype=np.float64)
    if mat.size == 0:
        raise ValueError("cannot take the centroid of an empty set")
    return mat.mean(axis=0)
