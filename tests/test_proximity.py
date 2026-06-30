import math

import numpy as np

from echo_veil.proximity import ProximityConfig, proximity_score, time_decay


def test_decay_at_zero_age_is_recency_weight():
    # At Δt=0: 0.15 * e^0 = 0.15
    cfg = ProximityConfig(time_constant_hours=12.0)
    assert math.isclose(time_decay(0.0, cfg), 0.15, abs_tol=1e-9)


def test_decay_at_one_time_constant():
    # At Δt=12: 0.15 * e^(-1) ≈ 0.0552
    cfg = ProximityConfig(time_constant_hours=12.0)
    assert math.isclose(time_decay(12.0, cfg), 0.15 * math.exp(-1.0), abs_tol=1e-9)


def test_identical_vectors_fresh_score():
    # cosine=1, Δt=0: 1.0 + 0.15 = 1.15
    v = np.array([1.0, 0.0, 0.0])
    assert math.isclose(proximity_score(v, v, age_hours=0.0), 1.15, abs_tol=1e-9)


def test_orthogonal_vectors_score_is_recency_only():
    # cosine=0, Δt=0: 0 + 0.15 = 0.15
    a = np.array([1.0, 0.0])
    b = np.array([0.0, 1.0])
    assert math.isclose(proximity_score(a, b, age_hours=0.0), 0.15, abs_tol=1e-9)


def test_negative_cosine_subtracts_from_score():
    # cosine=-1, Δt=0: -1.0 + 0.15 = -0.85
    a = np.array([1.0, 0.0])
    b = np.array([-1.0, 0.0])
    assert math.isclose(proximity_score(a, b, age_hours=0.0), -0.85, abs_tol=1e-9)


def test_score_decreases_with_age():
    v = np.array([1.0, 1.0])
    fresh = proximity_score(v, v, age_hours=0.0)
    stale = proximity_score(v, v, age_hours=10.0)
    assert stale < fresh
