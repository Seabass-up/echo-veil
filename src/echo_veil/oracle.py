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

from .archive import ColdArchive, MetadataIndex
from .caretaker import GardenersReport, gardeners_report
from .conflict import ConflictVine, FossilizedEcho
from .crypto_shield import CryptoShield, NullCryptoShield
from .drift import DriftDetector
from .vectors import Vector, centroid
from .vine import Vine, VineState
from .workspace import Workspace, WorkspaceConfig


class Oracle:
    def __init__(
        self,
        config: WorkspaceConfig | None = None,
        shield: CryptoShield | None = None,
        environment: str = "development",
    ) -> None:
        if environment == "production" and shield is None:
            raise RuntimeError(
                "Refusing to start in production without a real CryptoShield. "
                "The default NullCryptoShield provides no confidentiality."
            )
        self.environment = environment
        self.workspace = Workspace(config)
        self.index = MetadataIndex()
        self.archive = ColdArchive()
        self.drift = DriftDetector()
        self.shield: CryptoShield = shield or NullCryptoShield(silence_warning=True)
        self.conflicts: list[ConflictVine] = []
        self.fossils: list[FossilizedEcho] = []

    def sprout(self, topic: str, anchor: Vector) -> Vine:
        return self.workspace.add(Vine(topic=topic, anchor=anchor))

    def observe(self, intent: Vector, now: float | None = None) -> dict:
        """Process one query: update drift, run the decay cycle, archive evictions."""
        self.drift.observe(intent)
        report = self.workspace.run_decay_cycle(intent, now=now)
        for vine_id in report["evicted"]:
            vine = self.workspace.get(vine_id)
            if vine is not None:
                self.index.upsert(vine_id, vine.anchor, kind="anchor")
        return report

    def reinforce(self, vine_id: str, now: float | None = None) -> None:
        self.workspace.reinforce(vine_id, now=now)

    def garden_centroid(self) -> Vector | None:
        active = self.workspace.active()
        if not active:
            return None
        return centroid([v.anchor for v in active])

    def is_drifting(self) -> bool:
        gc = self.garden_centroid()
        if gc is None:
            return False
        return self.drift.is_drifting(gc)

    def report(self) -> GardenersReport:
        return gardeners_report(self.workspace, self.conflicts, self.fossils)
