import numpy as np
import pytest

from echo_veil import Oracle, WorkspaceConfig
from echo_veil.vine import VineState


def test_oracle_refuses_production_without_shield():
    with pytest.raises(RuntimeError):
        Oracle(environment="production")


def test_oracle_rejects_fake_shield_object():
    with pytest.raises(TypeError, match="shield must implement"):
        Oracle(environment="production", shield=object())


def test_oracle_rejects_incomplete_shield():
    class IncompleteShield:
        def protect(self, anchor):
            return anchor

    with pytest.raises(TypeError, match="shield must implement"):
        Oracle(environment="development", shield=IncompleteShield())


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


def test_custom_nonserializable_shield_keeps_plaintext_fallback_for_archive():
    class TupleShield:
        def protect(self, anchor):
            return ("protected", anchor.copy())

        def similarity(self, intent, protected_anchor):
            return 0.0

    o = Oracle(WorkspaceConfig(capacity=1, pressure_evict_at=0.0), shield=TupleShield())
    v = o.sprout("custom", np.array([1.0, 0.0], dtype=np.float64))

    assert v.protected_anchor is not None
    assert v.anchor.shape == (2,)

    o.observe(np.array([0.0, 1.0], dtype=np.float64))
    v.twilight_since -= 3600
    for _ in range(6):
        o.observe(np.array([0.0, 1.0], dtype=np.float64))

    assert len(o.index) == 1
    assert o.index.search(np.array([1.0, 0.0], dtype=np.float64), top_k=1)[0][0] == v.vine_id
    assert o.archive.get(v.vine_id) is not None
