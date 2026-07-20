"""The Oracle: a thin facade over the Echo Veil subsystems.

This is the convenience entry point. It wires together a Workspace, the lower
storage tiers, drift detection, and the conflict/fossil store, and exposes the
operations a host application actually performs:

  - sprout(topic, anchor)          add an active vine
  - observe(intent)                run a query cycle (decay + drift)
  - reinforce(vine_id)             snap a twilight vine back
  - forget(vine_id)                delete managed L1/L2/L3 state
  - report()                       the Gardener's Report

Confidence classification and the crypto shield are provided as collaborators
so callers can choose policy. By default the Oracle uses NullCryptoShield and
will REFUSE to start in 'production' mode without a real shield -- this keeps
the security gap explicit rather than silent.
"""

from __future__ import annotations

import math
import zlib
from numbers import Real
from threading import RLock
from typing import cast

import numpy as np

from .archive import (
    ColdArchive,
    EvictionRecord,
    IndexEntry,
    ArchiveBackend,
    MetadataIndex,
    MetadataIndexBackend,
    TransactionalEvictionStore,
    is_transactional_eviction_store,
)
from .capability import CapabilityReport, build_capability_report
from .caretaker import GardenersReport, gardeners_report
from .confidence import BandPolicy, ConfidenceBand, classify
from .conflict import ConflictVine, FossilizedEcho
from .crypto_shield import (
    AesGcmCryptoShield,
    CryptoShield,
    EnclaveCryptoShield,
    LocalOpenFheCryptoShield,
    NullCryptoShield,
    is_crypto_shield,
    is_production_crypto_shield,
    is_serializable_protected_payload,
)
from .drift import DriftDetector
from .proximity import proximity_score, time_decay
from .vectors import Vector, as_vector, centroid, cosine_similarity
from .vine import Vine, VineState
from .workspace import Workspace, WorkspaceConfig


class GenerationGated(Exception):
    """Raised when a confidence band gates generation and no override is given.

    Per spec Section 3, INFERENTIAL leaps require explicit user override and
    OBSCURITY faults are a hard stop. Callers should catch this and surface
    the appropriate escalation UI.
    """

    def __init__(self, band: ConfidenceBand, policy: BandPolicy) -> None:
        self.band = band
        self.policy = policy
        super().__init__(
            f"Generation gated by {policy.indicator} (band={band.value}). "
            f"Behavior: {policy.behavior}"
        )


class Oracle:
    def __init__(
        self,
        config: WorkspaceConfig | None = None,
        shield: CryptoShield | None = None,
        environment: str = "development",
        storage: TransactionalEvictionStore | None = None,
    ) -> None:
        if not isinstance(environment, str):
            raise TypeError("environment must be a string")
        normalized_environment = environment.strip().lower()
        if normalized_environment == "local":
            normalized_environment = "local-private"
        allowed_environments = {
            "development",
            "local-private",
            "test",
            "testing",
            "staging",
            "production",
        }
        if normalized_environment not in allowed_environments:
            raise ValueError(
                "environment must be one of: development, test, testing, "
                "local-private, staging, production"
            )
        if shield is not None and not is_crypto_shield(shield):
            raise TypeError(
                "shield must implement protect(anchor) and similarity(intent, protected_anchor)"
            )
        if storage is not None and not is_transactional_eviction_store(storage):
            raise TypeError(
                "storage must expose coordinated workspace, eviction, and deletion APIs"
            )
        if normalized_environment == "production" and not isinstance(
            shield, EnclaveCryptoShield
        ):
            raise RuntimeError(
                "Refusing to start in production without an attested "
                "EnclaveCryptoShield providing CKKS, hardware isolation, and the "
                "verified ZKP access gate."
            )
        if normalized_environment == "local-private" and not isinstance(
            shield, LocalOpenFheCryptoShield
        ):
            raise RuntimeError(
                "Refusing to start in local-private mode without a native "
                "LocalOpenFheCryptoShield."
            )
        if normalized_environment == "staging" and not (
            isinstance(shield, AesGcmCryptoShield)
            or (shield is not None and is_production_crypto_shield(shield))
        ):
            raise RuntimeError(
                "Refusing to start in staging without AES-GCM or an explicitly "
                "staging-ready CryptoShield."
            )
        self.environment = normalized_environment
        self.workspace = Workspace(config)
        self.storage = storage
        self.index: MetadataIndexBackend
        self.archive: ArchiveBackend
        if storage is None:
            self.index = MetadataIndex()
            self.archive = ColdArchive()
        else:
            self.index = storage.index
            self.archive = storage.archive
        self.drift = DriftDetector()
        selected_shield = (
            shield if shield is not None else NullCryptoShield(silence_warning=True)
        )
        self.shield = cast(CryptoShield, selected_shield)
        self.conflicts: list[ConflictVine] = []
        self.fossils: list[FossilizedEcho] = []
        persisted_dimension = getattr(self.index, "dimension", None)
        self._dimension: int | None = persisted_dimension
        self._lock = RLock()
        loader = getattr(storage, "load_workspace", None)
        if loader is not None:
            vines, cycles, crests = loader()
            self.workspace.restore_persistence_snapshot(vines, cycles, crests)
            workspace_dimension = next(
                (
                    vine.anchor.size
                    if vine.anchor.size
                    else int(getattr(vine.protected_anchor, "shape")[0])
                    if vine.protected_anchor is not None
                    else int(vine._anchor_shape[0])
                    for vine in vines
                ),
                None,
            )
            if self._dimension is None:
                self._dimension = workspace_dimension
            elif (
                workspace_dimension is not None
                and workspace_dimension != self._dimension
            ):
                raise RuntimeError("persisted L1 and L2 dimensions disagree")

    def sprout(self, topic: str, anchor: Vector) -> Vine:
        with self._lock:
            vine = Vine(topic=topic, anchor=anchor)
            dimension = vine.anchor.size
            self._validate_dimension(vine.anchor, establish=False)
            if not isinstance(self.shield, NullCryptoShield):
                protected_anchor = self.shield.protect(vine.anchor)
                if not is_serializable_protected_payload(protected_anchor):
                    raise TypeError(
                        "CryptoShield.protect() must return a payload with "
                        "to_json_bytes(); plaintext archive fallback is disabled"
                    )
                self._serialize_protected_payload(protected_anchor)
                vine.protected_anchor = protected_anchor
                vine.anchor = np.zeros(0, dtype=np.float64)
            added = self.workspace.add(vine)
            if self._dimension is None:
                self._dimension = dimension
            self._persist_workspace()
            return added

    def _persist_workspace(self) -> None:
        saver = getattr(self.storage, "save_workspace", None)
        if saver is None:
            return
        vines, cycles, crests = self.workspace.persistence_snapshot()
        saver(vines, cycles, crests)

    def _score_vine(self, intent: Vector, vine: Vine, now: float) -> float:
        if vine.protected_anchor is not None:
            similarity = self._protected_similarity(intent, vine.protected_anchor)
            return similarity + time_decay(
                vine.age_hours(now), self.workspace.config.proximity
            )
        anchor = (
            vine.anchor_snapshot() if vine.state == VineState.TWILIGHT else vine.anchor
        )
        return proximity_score(
            intent, anchor, vine.age_hours(now), self.workspace.config.proximity
        )

    def _reveal_protected_anchor(self, protected_anchor: object) -> Vector | None:
        reveal = getattr(self.shield, "reveal", None)
        if reveal is None:
            return None
        revealed = reveal(protected_anchor)
        return as_vector(
            cast(Vector, revealed),
            allow_empty=False,
            copy=True,
            name="revealed anchor vector",
        )

    def _score_index_entry(self, query: Vector, entry: IndexEntry) -> float:
        if entry.kind == "protected_anchor":
            return self._protected_similarity(query, entry.anchor)
        return cosine_similarity(query, entry.anchor)

    def _validate_dimension(self, vector: Vector, *, establish: bool) -> None:
        if self._dimension is None:
            if establish:
                self._dimension = vector.size
            return
        if vector.size != self._dimension:
            raise ValueError(
                f"dimension mismatch: expected ({self._dimension},), got {vector.shape}"
            )

    @staticmethod
    def _serialize_protected_payload(protected_anchor: object) -> bytes:
        if not is_serializable_protected_payload(protected_anchor):
            raise TypeError(
                "protected anchor must implement to_json_bytes(); "
                "plaintext archive fallback is disabled"
            )
        payload = protected_anchor.to_json_bytes()
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError(
                "protected payload serialization must return bytes-like data"
            )
        serialized = bytes(payload)
        if not serialized:
            raise ValueError("protected payload serialization must not be empty")
        return serialized

    def _protected_similarity(self, intent: Vector, protected_anchor: object) -> float:
        raw_similarity = self.shield.similarity(intent, protected_anchor)
        if isinstance(raw_similarity, bool) or not isinstance(raw_similarity, Real):
            raise TypeError(
                "CryptoShield.similarity() must return a finite cosine score"
            )
        similarity = float(raw_similarity)
        if not math.isfinite(similarity):
            raise ValueError(
                "CryptoShield.similarity() must return a finite cosine score"
            )
        tolerance = 1e-12
        if similarity < -1.0 - tolerance or similarity > 1.0 + tolerance:
            raise ValueError("CryptoShield.similarity() must return a score in [-1, 1]")
        return min(1.0, max(-1.0, similarity))

    def _archive_pending_evictions(self) -> None:
        """Idempotently archive every pending EVICTED vine, then prune it.

        Preparation and all writes complete before any vine is pruned. If a
        backend raises, pending vines remain reachable and the next observation
        retries them, including vines evicted during a previous failed call.
        """
        prepared: list[EvictionRecord] = []
        for vine in self.workspace.vines:
            if vine.state != VineState.EVICTED:
                continue
            if vine.protected_anchor is not None:
                payload = self._serialize_protected_payload(vine.protected_anchor)
                index_hint = self._reveal_protected_anchor(vine.protected_anchor)
                prepared.append(
                    EvictionRecord(
                        key=vine.vine_id,
                        anchor=vine.protected_anchor,
                        kind="protected_anchor",
                        archive_payload=payload,
                        dimension=self._eviction_dimension(vine),
                        metadata=self._eviction_metadata(vine),
                        index_hint=index_hint,
                    )
                )
                continue

            prepared_anchor = vine.anchor_snapshot()
            archive_payload = vine.archive_payload()
            if archive_payload is None:
                raw = prepared_anchor.astype(np.float64, copy=False).tobytes(order="C")
                archive_payload = zlib.compress(raw, level=9)
            prepared.append(
                EvictionRecord(
                    key=vine.vine_id,
                    anchor=prepared_anchor,
                    kind="anchor",
                    archive_payload=archive_payload,
                    dimension=prepared_anchor.size,
                    metadata=self._eviction_metadata(vine),
                )
            )

        if self.storage is not None:
            self.storage.commit_evictions(prepared)
            archived_ids = [record.key for record in prepared]
        else:
            archived_ids = []
            for record in prepared:
                self.archive.put(record.key, record.archive_payload)
                self.index.upsert(record.key, record.anchor, kind=record.kind)
                archived_ids.append(record.key)
        self.workspace.prune_evicted(archived_ids)

    def _eviction_dimension(self, vine: Vine) -> int:
        shape = getattr(vine.protected_anchor, "shape", None)
        if (
            isinstance(shape, tuple)
            and len(shape) == 1
            and isinstance(shape[0], int)
            and not isinstance(shape[0], bool)
            and shape[0] > 0
        ):
            return shape[0]
        if self._dimension is None:
            raise RuntimeError("cannot persist a protected anchor without a dimension")
        return self._dimension

    @staticmethod
    def _eviction_metadata(vine: Vine) -> dict[str, object]:
        return {
            "topic": vine.topic,
            "created_at": vine.created_at,
            "last_touched": vine.last_touched,
            "score": vine.score,
            "state": vine.state.value,
        }

    def observe(
        self,
        intent: Vector,
        now: float | None = None,
        cycles_since_twilight: dict[str, int] | None = None,
    ) -> dict:
        """Process one query: update drift, run the decay cycle, archive evictions.

        The full L1->L2->L3 pipeline is exercised here:
          - Evicted vines have their anchor indexed in L2 (MetadataIndex).
          - Evicted vine compressed payload is written to L3 (ColdArchive).
          - The vine is then pruned from the active workspace.
        """
        with self._lock:
            intent_vector = as_vector(
                intent,
                allow_empty=False,
                copy=True,
                name="intent vector",
            )
            self._validate_dimension(intent_vector, establish=True)
            report = self.workspace.run_decay_cycle(
                intent_vector,
                now=now,
                cycles_since_twilight=cycles_since_twilight,
                score_fn=self._score_vine,
            )
            self.drift.observe(intent_vector)
            self._archive_pending_evictions()
            self._persist_workspace()
            return report

    def search_index(self, query: Vector, top_k: int = 5) -> list[tuple[str, float]]:
        """Search L2 using the Oracle's shield-aware scorer."""
        with self._lock:
            query_vector = as_vector(
                query,
                allow_empty=False,
                name="query vector",
            )
            self._validate_dimension(query_vector, establish=False)
            return self.index.search(
                query_vector,
                top_k=top_k,
                score_fn=self._score_index_entry,
            )

    def archived_metadata(self, vine_id: str) -> dict[str, object] | None:
        """Return durable topic/lifecycle metadata when the backend supports it."""
        with self._lock:
            getter = getattr(self.storage, "get_eviction_metadata", None)
            if getter is None:
                return None
            result = getter(vine_id)
            if result is not None and not isinstance(result, dict):
                raise TypeError("storage metadata getter must return a dict or None")
            return cast(dict[str, object] | None, result)

    def forget(self, vine_id: str) -> bool:
        """Delete one memory from Echo Veil's managed L1/L2/L3 tiers.

        Durable backends delete their records before the live Vine is released,
        so a storage failure leaves a retryable in-memory object. Host payloads,
        backups, and separately managed conflict artifacts remain caller-owned.
        """
        MetadataIndex._validate_key(vine_id)
        with self._lock:
            live = self.workspace.get(vine_id)
            if self.storage is not None:
                deleted = self.storage.delete_memory(vine_id)
            else:
                removed_index = self.index.remove(vine_id)
                removed_archive = self.archive.remove(vine_id)
                deleted = removed_index or removed_archive
            removed = self.workspace.remove(vine_id)
            if removed is not None:
                removed.clear_material()
            return deleted or live is not None

    def reinforce(self, vine_id: str, now: float | None = None) -> None:
        with self._lock:
            self.workspace.reinforce(vine_id, now=now)
            self._persist_workspace()

    def lock(self, vine_id: str) -> None:
        """Apply and durably checkpoint an Amber Lock."""
        with self._lock:
            self.workspace.lock(vine_id)
            self._persist_workspace()

    def unlock(self, vine_id: str) -> None:
        """Remove and durably checkpoint an Amber Lock."""
        with self._lock:
            self.workspace.unlock(vine_id)
            self._persist_workspace()

    def set_crests(self, vine_ids: list[str]) -> None:
        """Set and durably checkpoint the focal crests."""
        with self._lock:
            self.workspace.set_crests(vine_ids)
            self._persist_workspace()

    def garden_centroid(self) -> Vector | None:
        with self._lock:
            active = self.workspace.active()
            if not active:
                return None
            anchors: list[Vector] = []
            for vine in active:
                if vine.protected_anchor is None or vine.anchor.size > 0:
                    anchors.append(vine.anchor)
                    continue
                revealed = self._reveal_protected_anchor(vine.protected_anchor)
                if revealed is not None:
                    anchors.append(revealed)
            if not anchors:
                return None
            return centroid(anchors)

    def is_drifting(self) -> bool:
        with self._lock:
            gc = self.garden_centroid()
            if gc is None:
                return False
            return self.drift.is_drifting(gc)

    def report(self) -> GardenersReport:
        with self._lock:
            return gardeners_report(self.workspace, self.conflicts, self.fossils)

    def capability_report(self) -> CapabilityReport:
        """Return a serializable defensive readiness report for host integration."""
        with self._lock:
            return build_capability_report(self)

    def doctor_report(self) -> CapabilityReport:
        """Alias for integrations that use doctor/readiness terminology."""
        return self.capability_report()

    def classify_confidence(self, score: float) -> BandPolicy:
        """Classify a confidence score and return the associated policy.

        If the policy's ``gates_generation`` flag is True, the caller should
        block generation and request an explicit user override (per spec
        Section 3, Confidence Spectrum Matrix).
        """
        return classify(score)

    def check_generation_gate(
        self,
        score: float,
        *,
        override: bool = False,
    ) -> BandPolicy:
        """Check whether a confidence score permits generation.

        Returns the BandPolicy for the score. If the policy gates generation
        (INFERENTIAL or OBSCURITY bands), raises ``GenerationGated`` unless
        ``override=True`` is passed (only meaningful for INFERENTIAL; OBSCURITY
        is a hard stop regardless of override).

        This implements the confidence gating the spec describes but the
        original code ignored: INFERENTIAL requires explicit user override,
        OBSCURITY is a hard stop with the 3-pronged escalation menu.
        """
        policy = classify(score)
        if policy.gates_generation:
            if policy.band == ConfidenceBand.OBSCURITY:
                # Hard stop; no override possible
                raise GenerationGated(policy.band, policy)
            if not override:
                raise GenerationGated(policy.band, policy)
        return policy
