import numpy as np

from echo_veil.drift import DriftDetector


def test_no_drift_when_aligned():
    d = DriftDetector()
    centroid = np.array([1.0, 0.0])
    for _ in range(3):
        d.observe(np.array([1.0, 0.0]))
    assert d.drift(centroid) < 1e-9
    assert d.is_drifting(centroid) is False


def test_drift_flag_latches_when_orthogonal():
    d = DriftDetector()
    centroid = np.array([1.0, 0.0])
    for _ in range(3):
        d.observe(np.array([0.0, 1.0]))  # orthogonal -> drift ~1.0
    assert d.is_drifting(centroid) is True


def test_hysteresis_prevents_single_sidebar_flip():
    d = DriftDetector()
    centroid = np.array([1.0, 0.0])
    # Establish aligned baseline.
    for _ in range(3):
        d.observe(np.array([1.0, 0.0]))
    assert d.is_drifting(centroid) is False
    # One orthogonal sidebar within a 3-window only moves the average ~1/3,
    # which stays inside the dead band and must NOT trip the alarm.
    d.observe(np.array([0.0, 1.0]))
    assert d.is_drifting(centroid) is False


def test_moving_average_window_is_bounded():
    d = DriftDetector(window=3)
    for i in range(5):
        d.observe(np.array([float(i), 0.0]))
    avg = d.moving_average()
    # Only the last 3 (2,3,4) should contribute -> mean 3.0
    assert np.allclose(avg, np.array([3.0, 0.0]))
