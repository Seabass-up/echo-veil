"""Level 1 active workspace and metabolism (Sections 1.1 and 2).

Responsibilities:
  - hold the active set of Vines
  - run the decay loop: score vines against the live intent, demote low-scoring
    ones to TWILIGHT, then evict them after the twilight window expires
  - honor Amber Locks (decay-immune) and the lock cap (12)
  - track Multi-Focal Crests and report the tidal-flow cache split

Constants taken verbatim from the spec:
  TWILIGHT_THRESHOLD = 0.42
  TWILIGHT_CYCLES     = 5         (or 30 minutes, whichever is longer)
  TWILIGHT_MINUTES    = 30
  REINFORCEMENT_BONUS = 0.08      (snap-back bonus)
  MAX_AMBER_LOCKS     = 12
  MAX_CRESTS          = 3
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .proximity import ProximityConfig, proximity_score
from .vectors import Vector
from .vine import Vine, VineState

TWILIGHT_THRESHOLD = 0.42
TWILIGHT_CYCLES = 5
TWILIGHT_MINUTES = 30
REINFORCEMENT_BONUS = 0.08
MAX_AMBER_LOCKS = 12
MAX_CRESTS = 3

# Tidal-flow cache split (Section 2, Multi-Focal Crests).
TIDAL_NORMAL = (0.70, 0.18, 0.12)
TIDAL_PRESSURE = (0.78, 0.14, 0.08)   # engaged when memory pressure > 90%
PRESSURE_TIGHTEN_AT = 0.90


@dataclass
class WorkspaceConfig:
    capacity: int = 400               # active-vine ceiling before pruning
    pressure_evict_at: float = 0.85   # RAM% that triggers a scan (spec: 85%)
    proximity: ProximityConfig = field(default_factory=ProximityConfig)


class Workspace:
    """The active runtime pool of vines."""

    def __init__(self, config: WorkspaceConfig | None = None) -> None:
        self.config = config or WorkspaceConfig()
        self._vines: dict[str, Vine] = {}
        self._crests: list[str] = []  # ordered: primary, secondary, tertiary

    # --- membership ----------------------------------------------------------
    def add(self, vine: Vine) -> Vine:
        self._vines[vine.vine_id] = vine
        return vine

    def get(self, vine_id: str) -> Vine | None:
        return self._vines.get(vine_id)

    @property
    def vines(self) -> list[Vine]:
        return list(self._vines.values())

    def active(self) -> list[Vine]:
        return [v for v in self._vines.values() if v.state == VineState.ACTIVE]

    def pressure(self) -> float:
        """Fraction of capacity currently occupied by non-evicted vines."""
        live = [v for v in self._vines.values() if v.state != VineState.EVICTED]
        return len(live) / self.config.capacity if self.config.capacity else 0.0

    # --- amber locks ---------------------------------------------------------
    def lock(self, vine_id: str) -> None:
        locked_count = sum(1 for v in self._vines.values() if v.locked)
        vine = self._vines[vine_id]
        if vine.locked:
            return
        if locked_count >= MAX_AMBER_LOCKS:
            raise ValueError(f"amber lock cap reached ({MAX_AMBER_LOCKS})")
        vine.locked = True

    def unlock(self, vine_id: str) -> None:
        self._vines[vine_id].locked = False

    # --- crests --------------------------------------------------------------
    def set_crests(self, vine_ids: list[str]) -> None:
        if len(vine_ids) > MAX_CRESTS:
            raise ValueError(f"at most {MAX_CRESTS} focal crests are supported")
        for vid in vine_ids:
            if vid not in self._vines:
                raise KeyError(f"unknown vine: {vid}")
        self._crests = list(vine_ids)

    def tidal_split(self) -> dict[str, float]:
        """Current cache allocation across active crests.

        Uses the tightened 78/14/08 split when memory pressure breaches 90%,
        otherwise the standard 70/18/12. Only as many slices as there are
        crests are returned.
        """
        weights = TIDAL_PRESSURE if self.pressure() > PRESSURE_TIGHTEN_AT else TIDAL_NORMAL
        labels = ["primary", "secondary", "tertiary"]
        return {labels[i]: weights[i] for i in range(len(self._crests))}

    # --- the decay loop ------------------------------------------------------
    def reinforce(self, vine_id: str, now: float | None = None) -> None:
        """Snap a twilight vine back to ACTIVE with the reinforcement bonus."""
        vine = self._vines[vine_id]
        if vine.state == VineState.TWILIGHT:
            vine.decompress()
            vine.state = VineState.ACTIVE
            vine.twilight_since = None
            vine.score = min(1.0, vine.score + REINFORCEMENT_BONUS)
        vine.touch(now)

    def _twilight_expired(self, vine: Vine, now: float, cycles_elapsed: int) -> bool:
        # "5 query cycles or 30 minutes, whichever is longer."
        if vine.twilight_since is None:
            return False
        minutes_elapsed = (now - vine.twilight_since) / 60.0
        return cycles_elapsed >= TWILIGHT_CYCLES and minutes_elapsed >= TWILIGHT_MINUTES

    def run_decay_cycle(
        self,
        intent: Vector,
        now: float | None = None,
        cycles_since_twilight: dict[str, int] | None = None,
    ) -> dict[str, list[str]]:
        """Score active vines against ``intent`` and advance the lifecycle.

        Returns a report of which vine ids moved where this cycle:
            {"demoted": [...], "evicted": [...]}

        ``cycles_since_twilight`` lets a caller drive the "5 query cycles" rule;
        when omitted, eviction falls back to the 30-minute clock alone.
        """
        now = time.time() if now is None else now
        cycles = cycles_since_twilight or {}
        report: dict[str, list[str]] = {"demoted": [], "evicted": []}

        # Only scan when memory pressure warrants it (spec: > 85%). The check is
        # advisory: callers can force a scan by lowering pressure_evict_at to 0.
        if self.pressure() < self.config.pressure_evict_at:
            # Still update scores so reporting is accurate, but skip eviction.
            self._rescore(intent, now)
            return report

        for vine in self._vines.values():
            if vine.state == VineState.EVICTED or vine.locked:
                continue

            vine.score = proximity_score(
                intent, vine.anchor, vine.age_hours(now), self.config.proximity
            )

            if vine.state == VineState.ACTIVE and vine.score < TWILIGHT_THRESHOLD:
                vine.state = VineState.TWILIGHT
                vine.twilight_since = now
                vine.compress()
                report["demoted"].append(vine.vine_id)

            elif vine.state == VineState.TWILIGHT:
                elapsed = cycles.get(vine.vine_id, TWILIGHT_CYCLES)
                if self._twilight_expired(vine, now, elapsed):
                    vine.state = VineState.EVICTED
                    report["evicted"].append(vine.vine_id)

        return report

    def _rescore(self, intent: Vector, now: float) -> None:
        for vine in self._vines.values():
            if vine.state != VineState.EVICTED and not vine.locked:
                vine.score = proximity_score(
                    intent, vine.anchor, vine.age_hours(now), self.config.proximity
                )
