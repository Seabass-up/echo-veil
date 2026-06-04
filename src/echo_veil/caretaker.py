"""Caretaker subsystems and the Gardener's Report (Section 4).

The caretaker summarizes workspace health into the spec's four designations:
  Thriving Vines   -> ACTIVE
  Twilight Grove   -> TWILIGHT
  Knotted Branches -> open conflicts
  Ancient Rings    -> fossils

This is the front-facing report surfaced on session re-entry.
"""

from __future__ import annotations

from dataclasses import dataclass

from .conflict import ConflictVine, FossilizedEcho
from .vine import VineState
from .workspace import Workspace


@dataclass
class GardenersReport:
    thriving_vines: int       # active
    twilight_grove: int       # hibernating
    knotted_branches: int     # open conflicts
    ancient_rings: int        # fossils
    memory_pressure: float    # 0..1

    def as_dict(self) -> dict:
        return {
            "thriving_vines": self.thriving_vines,
            "twilight_grove": self.twilight_grove,
            "knotted_branches": self.knotted_branches,
            "ancient_rings": self.ancient_rings,
            "memory_pressure": round(self.memory_pressure, 4),
        }


def gardeners_report(
    workspace: Workspace,
    conflicts: list[ConflictVine] | None = None,
    fossils: list[FossilizedEcho] | None = None,
) -> GardenersReport:
    conflicts = conflicts or []
    fossils = fossils or []
    states = [v.state for v in workspace.vines]
    return GardenersReport(
        thriving_vines=sum(1 for s in states if s == VineState.ACTIVE),
        twilight_grove=sum(1 for s in states if s == VineState.TWILIGHT),
        knotted_branches=sum(1 for c in conflicts if not c.resolved),
        ancient_rings=len(fossils),
        memory_pressure=workspace.pressure(),
    )
