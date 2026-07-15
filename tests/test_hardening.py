from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import numpy as np
import pytest

from echo_veil import (
    AesGcmCryptoShield,
    DriftDetector,
    Oracle,
    ProximityConfig,
    Vine,
    VineState,
    Workspace,
    WorkspaceConfig,
    classify,
)
from echo_veil.archive import ColdArchive, MetadataIndex
from echo_veil.conflict import FossilizedEcho, fossilize, open_conflict
from echo_veil.crypto_shield import ProtectedVector
from echo_veil.vectors import as_vector, cosine_similarity


@dataclass(frozen=True)
class _SerializablePayload:
    values: tuple[float, ...]

    @property
    def shape(self) -> tuple[int, ...]:
        return (len(self.values),)

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.values).encode("utf-8")


class _SerializableShield:
    def protect(self, anchor: np.ndarray) -> _SerializablePayload:
        return _SerializablePayload(tuple(float(value) for value in anchor))

    def similarity(
        self,
        intent: np.ndarray,
        protected_anchor: _SerializablePayload,
    ) -> float:
        return cosine_similarity(intent, protected_anchor.values)


class _FlakyArchive(ColdArchive):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    def put(self, key: str, payload: bytes) -> None:
        self.attempts += 1
        if self.attempts == 1:
            raise OSError("simulated archive outage")
        super().put(key, payload)


def test_stateful_vector_boundaries_copy_caller_arrays() -> None:
    source = np.array([1.0, 0.0], dtype=np.float64)
    vine = Vine("copy", source)
    detector = DriftDetector()
    detector.observe(source)
    index = MetadataIndex()
    index.upsert("copy", source)

    source[:] = [0.0, 1.0]

    assert np.array_equal(vine.anchor, np.array([1.0, 0.0]))
    assert np.array_equal(detector.moving_average(), np.array([1.0, 0.0]))
    assert index.search(np.array([1.0, 0.0]), top_k=1) == [("copy", 1.0)]


@pytest.mark.parametrize(
    "values",
    (
        np.array([], dtype=np.float64),
        np.array([np.nan, 0.0]),
        np.array([np.inf, 0.0]),
        np.array([-np.inf, 0.0]),
    ),
)
def test_invalid_vectors_are_rejected(values: np.ndarray) -> None:
    with pytest.raises(ValueError):
        as_vector(values)
    with pytest.raises(ValueError):
        Vine("invalid", values)


def test_configuration_and_query_limits_fail_closed() -> None:
    with pytest.raises(ValueError, match="positive"):
        WorkspaceConfig(capacity=0)
    with pytest.raises(ValueError, match="between 0 and 1"):
        WorkspaceConfig(pressure_evict_at=1.1)
    with pytest.raises(ValueError, match="positive"):
        ProximityConfig(time_constant_hours=0.0)
    with pytest.raises(ValueError, match="positive"):
        DriftDetector(window=0)
    with pytest.raises(ValueError, match="non-negative"):
        MetadataIndex().search(np.array([1.0]), top_k=-1)
    with pytest.raises(ValueError, match="out of range"):
        classify(float("nan"))


def test_environment_policy_normalizes_and_rejects_ambiguous_modes() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    oracle = Oracle(environment=" Production ", shield=shield)
    assert oracle.environment == "production"
    staging = Oracle(environment="staging", shield=shield)
    assert staging.capability_report().overall_status.value == "blocked"

    with pytest.raises(ValueError, match="environment must be one of"):
        Oracle(environment="prod", shield=shield)

    class UnmarkedShield(_SerializableShield):
        pass

    with pytest.raises(RuntimeError, match="production_ready=True"):
        Oracle(environment="production", shield=UnmarkedShield())


def test_serializable_custom_shield_never_keeps_plaintext_anchor() -> None:
    oracle = Oracle(shield=_SerializableShield())
    vine = oracle.sprout("protected", np.array([1.0, 0.0]))

    assert vine.anchor.size == 0
    assert isinstance(vine.protected_anchor, _SerializablePayload)
    assert oracle.observe(np.array([1.0, 0.0]))["demoted"] == []


def test_invalid_shield_score_cannot_partially_mutate_workspace() -> None:
    class BadScoreShield(_SerializableShield):
        def similarity(self, intent, protected_anchor):
            return float("nan")

    oracle = Oracle(shield=BadScoreShield())
    first = oracle.sprout("first", np.array([1.0, 0.0]))
    second = oracle.sprout("second", np.array([0.0, 1.0]))

    with pytest.raises(ValueError, match="finite cosine"):
        oracle.observe(np.array([1.0, 0.0]))

    assert first.state == VineState.ACTIVE
    assert second.state == VineState.ACTIVE
    assert first.score == 1.0
    assert second.score == 1.0
    assert oracle.drift.moving_average() is None


def test_failed_archive_write_keeps_eviction_pending_and_retryable() -> None:
    oracle = Oracle(WorkspaceConfig(capacity=2, pressure_evict_at=0.0))
    flaky_archive = _FlakyArchive()
    oracle.archive = flaky_archive
    vine = oracle.sprout("retry", np.array([0.0, 1.0]))
    now = time.time()

    oracle.observe(np.array([1.0, 0.0]), now=now)
    with pytest.raises(OSError, match="simulated"):
        oracle.observe(
            np.array([1.0, 0.0]),
            now=now + 31 * 60,
            cycles_since_twilight={vine.vine_id: 5},
        )

    assert vine.state == VineState.EVICTED
    assert oracle.workspace.get(vine.vine_id) is vine
    assert vine.anchor.size == 0

    # The next query retries previously pending evictions even though this
    # cycle's decay report does not newly evict the vine.
    retry_report = oracle.observe(np.array([1.0, 0.0]), now=now + 31 * 60 + 1)
    assert retry_report["evicted"] == []
    assert oracle.workspace.get(vine.vine_id) is None
    assert oracle.archive.get(vine.vine_id) is not None
    assert oracle.search_index(np.array([0.0, 1.0]), top_k=1)[0][0] == vine.vine_id
    # Indexing used a bounded snapshot and did not restore plaintext to the
    # externally retained evicted Vine object.
    assert vine.anchor.size == 0


def test_failed_fossilization_does_not_resolve_conflict() -> None:
    conflict = open_conflict("topic", "claim a", "claim b", 0.8, 0.7)

    with pytest.raises(ValueError, match="exceeds"):
        fossilize(conflict, "x" * 3_000)

    assert conflict.resolved is False


def test_timeline_event_overflow_rolls_back_mutation() -> None:
    echo = FossilizedEcho(topic="topic", summary="x" * 1_700)
    original_timeline = list(echo.timeline)

    with pytest.raises(ValueError, match="exceeds"):
        echo.record_event("oversized", "y" * 1_000)

    assert echo.timeline == original_timeline
    assert len(echo.serialize()) <= 2_048


def test_compressed_anchor_integrity_is_checked_without_state_mutation() -> None:
    vine = Vine("compressed", np.array([1.0, 0.0]))
    vine.compress()
    vine._compressed = b"not-zlib"

    with pytest.raises(ValueError, match="corrupt"):
        vine.anchor_snapshot()

    assert vine.anchor.size == 0
    assert vine._compressed == b"not-zlib"


def test_protected_vector_ciphertext_length_must_match_shape() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    protected = shield.protect(np.array([1.0, 0.0]))
    wrong_shape = ProtectedVector(
        algorithm=protected.algorithm,
        nonce=protected.nonce,
        ciphertext=protected.ciphertext,
        shape=(3,),
        dtype=protected.dtype,
    )

    with pytest.raises(ValueError, match="ciphertext size"):
        shield.similarity(np.array([1.0, 0.0, 0.0]), wrong_shape)


def test_workspace_rejects_duplicate_ids_and_dimensions() -> None:
    workspace = Workspace(WorkspaceConfig(capacity=4))
    first = workspace.add(Vine("first", np.array([1.0, 0.0]), vine_id="same"))

    with pytest.raises(ValueError, match="duplicate"):
        workspace.add(Vine("duplicate", np.array([0.0, 1.0]), vine_id="same"))
    with pytest.raises(ValueError, match="dimension mismatch"):
        workspace.add(Vine("wrong dimension", np.array([1.0, 0.0, 0.0])))

    workspace.set_crests([first.vine_id])
    first.state = VineState.EVICTED
    workspace.prune_evicted([first.vine_id])
    assert workspace.tidal_split() == {}


def test_cycle_overrides_reject_negative_counts() -> None:
    workspace = Workspace(WorkspaceConfig(capacity=2))
    vine = workspace.add(Vine("cycle", np.array([1.0, 0.0])))

    with pytest.raises(ValueError, match="non-negative"):
        workspace.run_decay_cycle(
            np.array([1.0, 0.0]),
            cycles_since_twilight={vine.vine_id: -1},
        )


def test_oracle_sprouts_are_serialized_across_threads() -> None:
    oracle = Oracle(WorkspaceConfig(capacity=128))

    def sprout(index: int) -> str:
        return oracle.sprout(f"vine-{index}", np.array([1.0, 0.0])).vine_id

    with ThreadPoolExecutor(max_workers=8) as executor:
        vine_ids = list(executor.map(sprout, range(100)))

    assert len(vine_ids) == len(set(vine_ids)) == 100
    assert len(oracle.workspace.vines) == 100
