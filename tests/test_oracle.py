import numpy as np
import pytest

from echo_veil import Oracle, WorkspaceConfig
from echo_veil.vine import VineState


def test_oracle_refuses_production_without_shield():
    with pytest.raises(RuntimeError):
        Oracle(environment="production")


def test_oracle_sprout_and_report():
    o = Oracle(WorkspaceConfig(capacity=5, pressure_evict_at=0.0))
    o.sprout("electrical estimate", np.array([1.0, 0.0]))
    o.sprout("family schedule", np.array([0.0, 1.0]))
    report = o.report()
    assert report.thriving_vines == 2
    assert report.twilight_grove == 0


def test_oracle_observe_demotes_offtopic_vine():
    o = Oracle(WorkspaceConfig(capacity=2, pressure_evict_at=0.0))
    keep = o.sprout("on topic", np.array([1.0, 0.0]))
    drop = o.sprout("off topic", np.array([0.0, 1.0]))
    o.observe(np.array([1.0, 0.0]))
    assert keep.state == VineState.ACTIVE
    assert drop.state == VineState.TWILIGHT
