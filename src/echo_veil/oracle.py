"""The Oracle: a thin facade over the Echo Veil subsystems.

This is the convenience entry point. It wires together a Workspace, the lower
storage tiers, drift detection, and the conflict/fossil store, and exposes the
operations a host application actually performs:

  - sprout(topic, anchor)          add an active vine
  - observe(intent)                run a query cycle (decay + drift)
  - reinforce(vine_id)             snap a twilight vine back
  - report()                       the Gardener's Report

Confidence classification and the crypto shield are provided as collaborators
so callers can choose policy. By default the Oracle uses NullCryptoShield and
will REFUSE to start in 'production' mode without a real shield -- this keeps
the security gap explicit rather than silent.
"""

from __future__ import annotations

import zlib
from typing import cast

import numpy as np

from .archive import ColdArchive, IndexEntry, MetadataIndex
from .capability import CapabilityReport, build_capability_report
from .caretaker import GardenersReport, gardeners_report
from .confidence import BandPolicy, ConfidenceBand, classify
from .conflict import ConflictVine, FossilizedEcho
from .crypto_shield import (
    CryptoShield,
    NullCryptoShield,
    ProtectedVector,
    is_crypto_shield,
    is_serializable_protected_payload,
)
from .drift import DriftDetector
from .proximity import proximity_score, time_decay
from .vectors import Vector, centroid
from .vine import Vine
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
    ) -> None:
        if shield is not None and not is_crypto_shield(shield):
            raise TypeError("shield must implement protect(anchor) and similarity(intent, protected_anchor)")
        if environment == "production" and (shield is None or isinstance(shield, NullCryptoShield)):
            raise RuntimeError(
                "Refusing to start in production without a real CryptoShield. "
                "NullCryptoShield provides no confidentiality."
            )
        self.environment = environment
        self.workspace = Workspace(config)
        self.index = MetadataIndex()
        self.archive = ColdArchive()
        self.drift = DriftDetector()
        selected_shield = shield if shield is not None else NullCryptoShield(silence_warning=True)
        self.shield = cast(CryptoShield, selected_shield)
        self.conflicts: list[ConflictVine] = []
        self.fossils: list[FossilizedEcho] = []

    def sprout(self, topic: str, anchor: Vector) -> Vine:
        vine = Vine(topic=topic, anchor=anchor)
        if not isinstance(self.shield, NullCryptoShield):
            protected_anchor = self.shield.protect(vine.anchor)
            vine.protected_anchor = protected_anchor
            if is_serializable_protected_payload(protected_anchor):
                vine.anchor = np.zeros(0, dtype=np.float64)
        return self.workspace.add(vine)

    def _score_vine(self, intent: Vector, vine: Vine, now: float) -> float:
        if vine.protected_anchor is not None:
            similarity = self.shield.similarity(intent, vine.protected_anchor)
            return similarity + time_decay(vine.age_hours(now), self.workspace.config.proximity)
        return proximity_score(intent, vine.anchor, vine.age_hours(now), self.workspace.config.proximity)

    def _reveal_protected_anchor(self, protected_anchor: object) -> Vector | None:
        reveal = getattr(self.shield, "reveal", None)
        if reveal is None:
            return None
        revealed = reveal(protected_anchor)
        return cast(Vector, revealed)

    def _score_index_entry(self, query: Vector, entry: IndexEntry) -> float:
        if isinstance(entry.anchor, ProtectedVector):
            return self.shield.similarity(query, entry.anchor)
        return proximity_score(
            query,
            entry.anchor,
            age_hours=0.0,
            config=self.workspace.config.proximity,
        )

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
        self.drift.observe(intent)
        report = self.workspace.run_decay_cycle(
            intent,
            now=now,
            cycles_since_twilight=cycles_since_twilight,
            score_fn=self._score_vine,
        )
        for vine_id in report["evicted"]:
            vine = self.workspace.get(vine_id)
            if vine is not None:
                if vine.protected_anchor is not None and is_serializable_protected_payload(vine.protected_anchor):
                    self.index.upsert(vine_id, vine.protected_anchor, kind="protected_anchor")
                    self.archive.put(vine_id, vine.protected_anchor.to_json_bytes())
                    continue
                # Decompress to get the anchor for L2 indexing
                vine.decompress()
                self.index.upsert(vine_id, vine.anchor, kind="anchor")
                # Compress anchor for L3 cold archive storage
                raw = vine.anchor.astype(np.float64).tobytes()
                self.archive.put(vine_id, zlib.compress(raw, level=9))
        # Prune evicted vines after archiving
        self.workspace.prune_evicted()
        return report

    def search_index(self, query: Vector, top_k: int = 5) -> list[tuple[str, float]]:
        """Search L2 using the Oracle's shield-aware scorer."""
        return self.index.search(query, top_k=top_k, score_fn=self._score_index_entry)

    def reinforce(self, vine_id: str, now: float | None = None) -> None:
        self.workspace.reinforce(vine_id, now=now)

    def garden_centroid(self) -> Vector | None:
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
        gc = self.garden_centroid()
        if gc is None:
            return False
        return self.drift.is_drifting(gc)

    def report(self) -> GardenersReport:
        return gardeners_report(self.workspace, self.conflicts, self.fossils)

    def capability_report(self) -> CapabilityReport:
        """Return a serializable defensive readiness report for host integration."""
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
        self, score: float, *, override: bool = False,
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
