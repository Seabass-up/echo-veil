import time

import numpy as np
import pytest

from echo_veil.vine import Vine, VineState
from echo_veil.workspace import (
    MAX_AMBER_LOCKS,
    MAX_CRESTS,
    TWILIGHT_THRESHOLD,
    Workspace,
    WorkspaceConfig,
)


def _ws(capacity=2, evict_at=0.0):
    # evict_at=0.0 forces the scan to always run, for deterministic tests.
    return Workspace(WorkspaceConfig(capacity=capacity, pressure_evict_at=evict_at))


def test_low_score_vine_demoted_to_twilight():
    ws = _ws()
    on_topic = ws.add(Vine("a", np.array([1.0, 0.0])))
    off_topic = ws.add(Vine("b", np.array([0.0, 1.0])))
    intent = np.array([1.0, 0.0])

    ws.run_decay_cycle(intent)

    assert on_topic.state == VineState.ACTIVE
    assert off_topic.state == VineState.TWILIGHT
    assert off_topic.score < TWILIGHT_THRESHOLD


def test_locked_vine_never_decays():
    ws = _ws()
    v = ws.add(Vine("locked", np.array([0.0, 1.0])))  # orthogonal to intent
    ws.lock(v.vine_id)
    ws.run_decay_cycle(np.array([1.0, 0.0]))
    assert v.state == VineState.ACTIVE


def test_amber_lock_cap_enforced():
    ws = Workspace(WorkspaceConfig(capacity=100))
    ids = [
        ws.add(Vine(f"v{i}", np.array([1.0, 0.0]))).vine_id
        for i in range(MAX_AMBER_LOCKS + 1)
    ]
    for vid in ids[:MAX_AMBER_LOCKS]:
        ws.lock(vid)
    with pytest.raises(ValueError):
        ws.lock(ids[MAX_AMBER_LOCKS])


def test_reinforce_snaps_back_with_bonus():
    ws = _ws()
    v = ws.add(Vine("b", np.array([0.0, 1.0]), score=0.30))
    ws.run_decay_cycle(np.array([1.0, 0.0]))
    assert v.state == VineState.TWILIGHT
    before = v.score
    ws.reinforce(v.vine_id)
    assert v.state == VineState.ACTIVE
    assert v.score == pytest.approx(before + 0.08)


def test_twilight_evicts_after_window():
    ws = _ws()
    v = ws.add(Vine("b", np.array([0.0, 1.0])))
    now = time.time()
    ws.run_decay_cycle(np.array([1.0, 0.0]), now=now)
    assert v.state == VineState.TWILIGHT

    # Advance 31 minutes and supply >=5 cycles elapsed.
    later = now + 31 * 60
    ws.run_decay_cycle(
        np.array([1.0, 0.0]), now=later, cycles_since_twilight={v.vine_id: 5}
    )
    assert v.state == VineState.EVICTED


def test_crest_cap_enforced():
    ws = Workspace(WorkspaceConfig(capacity=100))
    ids = [
        ws.add(Vine(f"v{i}", np.array([1.0, 0.0]))).vine_id
        for i in range(MAX_CRESTS + 1)
    ]
    with pytest.raises(ValueError):
        ws.set_crests(ids)


def test_tidal_split_normal_and_pressure():
    ws = Workspace(WorkspaceConfig(capacity=10))
    ids = [ws.add(Vine(f"v{i}", np.array([1.0, 0.0]))).vine_id for i in range(3)]
    ws.set_crests(ids)
    split = ws.tidal_split()
    assert split == {"primary": 0.70, "secondary": 0.18, "tertiary": 0.12}

    # Drive pressure > 90% by filling capacity.
    full = Workspace(WorkspaceConfig(capacity=3))
    fids = [full.add(Vine(f"v{i}", np.array([1.0, 0.0]))).vine_id for i in range(3)]
    full.set_crests(fids)
    assert full.pressure() > 0.90
    assert full.tidal_split() == {"primary": 0.78, "secondary": 0.14, "tertiary": 0.08}


def test_compression_roundtrip_preserves_anchor():
    v = Vine("x", np.arange(768, dtype=float))
    original = v.anchor.copy()
    ratio = v.compress()
    assert 0.0 <= ratio < 1.0
    v.decompress()
    assert np.allclose(v.anchor, original)


def test_default_pressure_no_longer_blocks_decay():
    ws = Workspace(WorkspaceConfig(capacity=100))
    v = ws.add(Vine("off-topic", np.array([0.0, 1.0])))

    report = ws.run_decay_cycle(np.array([1.0, 0.0]))

    assert v.state == VineState.TWILIGHT
    assert v.vine_id in report["demoted"]


def test_capacity_overflow_evicts_lowest_scoring_vines():
    ws = Workspace(WorkspaceConfig(capacity=2))
    keep = ws.add(Vine("keep", np.array([1.0, 0.0])))
    middle = ws.add(Vine("middle", np.array([0.5, 0.5])))
    drop = ws.add(Vine("drop", np.array([0.0, 1.0])))

    report = ws.run_decay_cycle(np.array([1.0, 0.0]))

    assert keep.state != VineState.EVICTED
    assert middle.state != VineState.EVICTED
    assert drop.state == VineState.EVICTED
    assert drop.vine_id in report["evicted"]
    assert ws.pressure() == pytest.approx(1.0)


def test_protected_vine_without_oracle_score_fn_does_not_crash_decay():
    ws = Workspace(WorkspaceConfig(capacity=2))
    v = ws.add(Vine("protected", np.zeros(0), protected_anchor=object()))

    report = ws.run_decay_cycle(np.array([1.0, 0.0]))

    assert report == {"demoted": [], "evicted": []}
    assert v.state == VineState.ACTIVE


def test_manual_twilight_vine_gets_internal_counter_and_expires():
    ws = Workspace(WorkspaceConfig(capacity=2))
    v = ws.add(Vine("manual", np.array([0.0, 1.0])))
    now = time.time()
    v.state = VineState.TWILIGHT
    v.twilight_since = now - 31 * 60

    for _ in range(6):
        ws.run_decay_cycle(np.array([1.0, 0.0]), now=now)

    assert v.state == VineState.EVICTED
