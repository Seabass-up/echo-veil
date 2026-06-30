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
from collections.abc import Callable
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
    pressure_evict_at: float = 0.85   # retained for compatibility; decay always scans
    proximity: ProximityConfig = field(default_factory=ProximityConfig)


class Workspace:
    """The active runtime pool of vines."""

    def __init__(self, config: WorkspaceConfig | None = None) -> None:
        self.config = config or WorkspaceConfig()
        self._vines: dict[str, Vine] = {}
        self._crests: list[str] = []  # ordered: primary, secondary, tertiary
        self._twilight_cycles: dict[str, int] = {}  # internal cycle counter

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

    def prune_evicted(self) -> list[str]:
        """Remove evicted vines from the workspace dict and return their ids.

        Callers (typically the Oracle) should archive evicted vine data to L2/L3
        *before* calling this method, since the vine objects become unreachable
        afterward. This two-step pattern (observe ? archive ? prune) prevents
        memory leaks while giving the archiving layer time to read the data.
        """
        evicted_ids = [vid for vid, v in list(self._vines.items()) if v.state == VineState.EVICTED]
        for vid in evicted_ids:
            del self._vines[vid]
            self._twilight_cycles.pop(vid, None)
        return evicted_ids

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
            self._twilight_cycles.pop(vine_id, None)
        vine.touch(now)

    def _twilight_expired(self, vine: Vine, now: float) -> bool:
        """Check if a twilight vine has exceeded both the cycle and time thresholds.

        The spec requires "5 query cycles or 30 minutes, whichever is longer"
        (i.e. both conditions must be met before eviction).
        """
        if vine.twilight_since is None:
            return False
        minutes_elapsed = (now - vine.twilight_since) / 60.0
        cycles_elapsed = self._twilight_cycles.get(vine.vine_id, 0)
        return cycles_elapsed >= TWILIGHT_CYCLES and minutes_elapsed >= TWILIGHT_MINUTES

    def run_decay_cycle(
        self,
        intent: Vector,
        now: float | None = None,
        cycles_since_twilight: dict[str, int] | None = None,
        score_fn: Callable[[Vector, Vine, float], float] | None = None,
    ) -> dict[str, list[str]]:
        """Score active vines against ``intent`` and advance the lifecycle.

        Returns a report of which vine ids moved where this cycle:
            {"demoted": [...], "evicted": [...]}

        ``cycles_since_twilight`` lets a caller drive the "5 query cycles" rule;
        when omitted, the internal cycle counter is used instead.

        Evicted vines remain in the workspace dict until ``prune_evicted()`` is
        called, giving the archiving layer (e.g. the Oracle) a chance to read
        their data for L2/L3 transfer.
        """
        now = time.time() if now is None else now
        caller_cycles = cycles_since_twilight or {}
        report: dict[str, list[str]] = {"demoted": [], "evicted": []}

        for vine in list(self._vines.values()):
            if vine.state == VineState.EVICTED or vine.locked:
                continue

            # Only rescore ACTIVE vines; TWILIGHT vines have their anchor
            # compressed (zeroed) so proximity cannot be recomputed. Their
            # score from demotion is preserved until reinforcement or eviction.
            if vine.state == VineState.ACTIVE:
                vine.score = self._score_active_vine(intent, vine, now, score_fn=score_fn)

            if vine.state == VineState.ACTIVE and vine.score < TWILIGHT_THRESHOLD:
                vine.state = VineState.TWILIGHT
                vine.twilight_since = now
                if vine.protected_anchor is None:
                    vine.compress()
                self._twilight_cycles[vine.vine_id] = 0
                report["demoted"].append(vine.vine_id)

            elif vine.state == VineState.TWILIGHT:
                if vine.twilight_since is None:
                    vine.twilight_since = now
                self._twilight_cycles.setdefault(vine.vine_id, 0)

                # Increment internal cycle counter
                if vine.vine_id in self._twilight_cycles:
                    self._twilight_cycles[vine.vine_id] += 1

                # Allow caller override for cycle count
                if vine.vine_id in caller_cycles:
                    elapsed = caller_cycles[vine.vine_id]
                    self._twilight_cycles[vine.vine_id] = elapsed
                else:
                    elapsed = self._twilight_cycles.get(vine.vine_id, 0)

                if self._twilight_expired(vine, now):
                    vine.state = VineState.EVICTED
                    report["evicted"].append(vine.vine_id)

        self._enforce_capacity(report)
        return report

    def _enforce_capacity(self, report: dict[str, list[str]]) -> None:
        if self.config.capacity <= 0:
            return
        live = [v for v in self._vines.values() if v.state != VineState.EVICTED]
        overflow = len(live) - self.config.capacity
        if overflow <= 0:
            return

        candidates = [v for v in live if not v.locked]
        candidates.sort(key=lambda v: (v.score, v.last_touched))
        for vine in candidates[:overflow]:
            if vine.state == VineState.ACTIVE and vine.protected_anchor is None:
                vine.compress()
            vine.state = VineState.EVICTED
            self._twilight_cycles.pop(vine.vine_id, None)
            if vine.vine_id not in report["evicted"]:
                report["evicted"].append(vine.vine_id)

    def _rescore(
        self,
        intent: Vector,
        now: float,
        *,
        score_fn: Callable[[Vector, Vine, float], float] | None = None,
    ) -> None:
        for vine in self._vines.values():
            if vine.state == VineState.ACTIVE and not vine.locked:
                vine.score = self._score_active_vine(intent, vine, now, score_fn=score_fn)

    def _score_active_vine(
        self,
        intent: Vector,
        vine: Vine,
        now: float,
        *,
        score_fn: Callable[[Vector, Vine, float], float] | None = None,
    ) -> float:
        if score_fn is not None:
            return score_fn(intent, vine, now)
        if vine.protected_anchor is not None and vine.anchor.shape == (0,):
            return vine.score
        return proximity_score(intent, vine.anchor, vine.age_hours(now), self.config.proximity)
