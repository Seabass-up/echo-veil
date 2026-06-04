import math

import numpy as np

from echo_veil.proximity import ProximityConfig, proximity_score, time_decay


def test_decay_halves_at_half_life():
    cfg = ProximityConfig(half_life_hours=6.0)
    assert math.isclose(time_decay(0.0, cfg), 1.0, abs_tol=1e-9)
    assert math.isclose(time_decay(6.0, cfg), 0.5, abs_tol=1e-9)
    assert math.isclose(time_decay(12.0, cfg), 0.25, abs_tol=1e-9)


def test_identical_vectors_fresh_score_is_one():
    v = np.array([1.0, 0.0, 0.0])
    assert math.isclose(proximity_score(v, v, age_hours=0.0), 1.0, abs_tol=1e-9)


def test_orthogonal_vectors_score_zero():
    a = np.array([1.0, 0.0])
    b = np.array([0.0, 1.0])
    assert proximity_score(a, b, age_hours=0.0) == 0.0


def test_negative_cosine_clamped_to_zero():
    a = np.array([1.0, 0.0])
    b = np.array([-1.0, 0.0])
    assert proximity_score(a, b, age_hours=0.0) == 0.0


def test_score_decreases_with_age():
    v = np.array([1.0, 1.0])
    fresh = proximity_score(v, v, age_hours=0.0)
    stale = proximity_score(v, v, age_hours=10.0)
    assert stale < fresh
