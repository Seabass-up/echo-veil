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

import math
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from numbers import Real
from threading import RLock

from .proximity import ProximityConfig, proximity_score
from .vectors import Vector, as_vector
from .vine import Vine, VineState

TWILIGHT_THRESHOLD = 0.42
TWILIGHT_CYCLES = 5
TWILIGHT_MINUTES = 30
REINFORCEMENT_BONUS = 0.08
MAX_AMBER_LOCKS = 12
MAX_CRESTS = 3

# Tidal-flow cache split (Section 2, Multi-Focal Crests).
TIDAL_NORMAL = (0.70, 0.18, 0.12)
TIDAL_PRESSURE = (0.78, 0.14, 0.08)  # engaged when memory pressure > 90%
PRESSURE_TIGHTEN_AT = 0.90


@dataclass(frozen=True)
class WorkspaceConfig:
    capacity: int = 400  # active-vine ceiling before pruning
    pressure_evict_at: float = 0.85  # retained for compatibility; decay always scans
    proximity: ProximityConfig = field(default_factory=ProximityConfig)

    def __post_init__(self) -> None:
        if isinstance(self.capacity, bool) or not isinstance(self.capacity, int):
            raise TypeError("capacity must be a positive integer")
        if self.capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        if isinstance(self.pressure_evict_at, bool) or not isinstance(
            self.pressure_evict_at, Real
        ):
            raise TypeError("pressure_evict_at must be between 0 and 1")
        threshold = float(self.pressure_evict_at)
        if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise ValueError("pressure_evict_at must be between 0 and 1")
        object.__setattr__(self, "pressure_evict_at", threshold)
        if not isinstance(self.proximity, ProximityConfig):
            raise TypeError("proximity must be a ProximityConfig")


class Workspace:
    """The active runtime pool of vines."""

    def __init__(self, config: WorkspaceConfig | None = None) -> None:
        if config is not None and not isinstance(config, WorkspaceConfig):
            raise TypeError("config must be a WorkspaceConfig")
        self.config = WorkspaceConfig() if config is None else config
        self._vines: dict[str, Vine] = {}
        self._crests: list[str] = []  # ordered: primary, secondary, tertiary
        self._twilight_cycles: dict[str, int] = {}  # internal cycle counter
        self._dimension: int | None = None
        self._lock = RLock()

    # --- membership ----------------------------------------------------------
    def add(self, vine: Vine) -> Vine:
        if not isinstance(vine, Vine):
            raise TypeError("vine must be a Vine")
        with self._lock:
            if vine.vine_id in self._vines:
                raise ValueError(f"duplicate vine id: {vine.vine_id}")
            dimension: int | None = vine.anchor.size if vine.anchor.size > 0 else None
            protected_shape = getattr(vine.protected_anchor, "shape", None)
            if (
                dimension is None
                and isinstance(protected_shape, tuple)
                and len(protected_shape) == 1
                and isinstance(protected_shape[0], int)
                and not isinstance(protected_shape[0], bool)
                and protected_shape[0] > 0
            ):
                dimension = protected_shape[0]
            if dimension is not None:
                if self._dimension is None:
                    self._dimension = dimension
                elif dimension != self._dimension:
                    raise ValueError(
                        f"dimension mismatch: expected ({self._dimension},), "
                        f"got ({dimension},)"
                    )
            self._vines[vine.vine_id] = vine
            return vine

    def get(self, vine_id: str) -> Vine | None:
        with self._lock:
            return self._vines.get(vine_id)

    def remove(self, vine_id: str) -> Vine | None:
        """Remove one vine and its lifecycle bookkeeping from live memory."""
        if not isinstance(vine_id, str) or not vine_id.strip():
            raise ValueError("vine_id must be a non-empty string")
        with self._lock:
            vine = self._vines.pop(vine_id, None)
            self._twilight_cycles.pop(vine_id, None)
            self._crests = [crest for crest in self._crests if crest != vine_id]
            return vine

    @property
    def vines(self) -> list[Vine]:
        with self._lock:
            return list(self._vines.values())

    def active(self) -> list[Vine]:
        with self._lock:
            return [v for v in self._vines.values() if v.state == VineState.ACTIVE]

    def persistence_snapshot(
        self,
    ) -> tuple[list[Vine], dict[str, int], tuple[str, ...]]:
        """Return a detached snapshot suitable for an atomic durable checkpoint."""
        with self._lock:
            vines: list[Vine] = []
            for source in self._vines.values():
                snapshot_anchor = (
                    source.anchor_snapshot()
                    if source._compressed is not None
                    else source.anchor.copy()
                )
                clone = Vine(
                    topic=source.topic,
                    anchor=snapshot_anchor,
                    vine_id=source.vine_id,
                    created_at=source.created_at,
                    last_touched=source.last_touched,
                    state=source.state,
                    locked=source.locked,
                    score=source.score,
                    twilight_since=source.twilight_since,
                    protected_anchor=source.protected_anchor,
                )
                clone._compressed = source._compressed
                clone._anchor_shape = source._anchor_shape
                if source._compressed is not None:
                    clone.anchor = source.anchor.copy()
                vines.append(clone)
            return vines, dict(self._twilight_cycles), tuple(self._crests)

    def restore_persistence_snapshot(
        self,
        vines: list[Vine],
        twilight_cycles: dict[str, int],
        crests: tuple[str, ...],
    ) -> None:
        """Restore a validated durable checkpoint into an empty workspace."""
        if not isinstance(vines, list) or not all(
            isinstance(vine, Vine) for vine in vines
        ):
            raise TypeError("persisted vines must be a list of Vine objects")
        cycles = self._validate_cycle_overrides(twilight_cycles)
        with self._lock:
            if self._vines:
                raise RuntimeError("workspace restore requires an empty workspace")
            for vine in vines:
                self.add(vine)
            unknown_cycles = set(cycles) - set(self._vines)
            if unknown_cycles:
                raise ValueError("persisted twilight cycles reference unknown vines")
            if any(vine_id not in self._vines for vine_id in crests):
                raise ValueError("persisted crests reference unknown vines")
            self._twilight_cycles = cycles
            self._crests = list(crests)

    def pressure(self) -> float:
        """Fraction of capacity currently occupied by non-evicted vines."""
        with self._lock:
            live_count = sum(
                1 for vine in self._vines.values() if vine.state != VineState.EVICTED
            )
            return live_count / self.config.capacity

    def prune_evicted(self, vine_ids: Iterable[str] | None = None) -> list[str]:
        """Remove evicted vines from the workspace dict and return their ids.

        Callers (typically the Oracle) should archive evicted vine data to L2/L3
        *before* calling this method, since the vine objects become unreachable
        afterward. This two-step pattern (observe ? archive ? prune) prevents
        memory leaks while giving the archiving layer time to read the data.
        """
        with self._lock:
            requested = None if vine_ids is None else set(vine_ids)
            evicted_ids = [
                vid
                for vid, vine in self._vines.items()
                if vine.state == VineState.EVICTED
                and (requested is None or vid in requested)
            ]
            for vid in evicted_ids:
                del self._vines[vid]
                self._twilight_cycles.pop(vid, None)
            if evicted_ids:
                removed = set(evicted_ids)
                self._crests = [vid for vid in self._crests if vid not in removed]
            return evicted_ids

    # --- amber locks ---------------------------------------------------------
    def lock(self, vine_id: str) -> None:
        with self._lock:
            locked_count = sum(1 for vine in self._vines.values() if vine.locked)
            vine = self._vines[vine_id]
            if vine.state == VineState.EVICTED:
                raise ValueError("cannot lock an evicted vine")
            if vine.locked:
                return
            if locked_count >= MAX_AMBER_LOCKS:
                raise ValueError(f"amber lock cap reached ({MAX_AMBER_LOCKS})")
            vine.locked = True

    def unlock(self, vine_id: str) -> None:
        with self._lock:
            self._vines[vine_id].locked = False

    # --- crests --------------------------------------------------------------
    def set_crests(self, vine_ids: list[str]) -> None:
        if not isinstance(vine_ids, list):
            raise TypeError("vine_ids must be a list")
        if not all(isinstance(vine_id, str) and vine_id for vine_id in vine_ids):
            raise ValueError("focal crest ids must be non-empty strings")
        if len(vine_ids) > MAX_CRESTS:
            raise ValueError(f"at most {MAX_CRESTS} focal crests are supported")
        if len(set(vine_ids)) != len(vine_ids):
            raise ValueError("focal crest ids must be unique")
        with self._lock:
            for vid in vine_ids:
                vine = self._vines.get(vid)
                if vine is None:
                    raise KeyError(f"unknown vine: {vid}")
                if vine.state == VineState.EVICTED:
                    raise ValueError(f"cannot crest an evicted vine: {vid}")
            self._crests = list(vine_ids)

    def tidal_split(self) -> dict[str, float]:
        """Current cache allocation across active crests.

        Uses the tightened 78/14/08 split when memory pressure breaches 90%,
        otherwise the standard 70/18/12. Only as many slices as there are
        crests are returned.
        """
        with self._lock:
            weights = (
                TIDAL_PRESSURE
                if self.pressure() > PRESSURE_TIGHTEN_AT
                else TIDAL_NORMAL
            )
            labels = ["primary", "secondary", "tertiary"]
            return {labels[i]: weights[i] for i in range(len(self._crests))}

    # --- the decay loop ------------------------------------------------------
    def reinforce(self, vine_id: str, now: float | None = None) -> None:
        """Snap a twilight vine back to ACTIVE with the reinforcement bonus."""
        with self._lock:
            vine = self._vines[vine_id]
            if vine.state == VineState.EVICTED:
                raise ValueError("cannot reinforce an evicted vine")
            if vine.state == VineState.TWILIGHT:
                if vine.protected_anchor is None:
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
        twilight_since = Vine._validate_timestamp(
            vine.twilight_since,
            "twilight_since",
        )
        minutes_elapsed = (now - twilight_since) / 60.0
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
        current_time = time.time() if now is None else now
        if isinstance(current_time, bool) or not isinstance(current_time, Real):
            raise TypeError("now must be a finite non-negative timestamp")
        current_time = float(current_time)
        if not math.isfinite(current_time) or current_time < 0.0:
            raise ValueError("now must be a finite non-negative timestamp")
        intent_vector = as_vector(
            intent,
            allow_empty=False,
            name="intent vector",
        )
        caller_cycles = self._validate_cycle_overrides(cycles_since_twilight)
        report: dict[str, list[str]] = {"demoted": [], "evicted": []}

        with self._lock:
            if self._dimension is not None and intent_vector.size != self._dimension:
                raise ValueError(
                    f"dimension mismatch: expected ({self._dimension},), "
                    f"got {intent_vector.shape}"
                )
            # Score first so a failing/custom scorer cannot leave half the
            # active set updated and half untouched.
            live_scores = {
                vine.vine_id: self._score_active_vine(
                    intent_vector,
                    vine,
                    current_time,
                    score_fn=score_fn,
                )
                for vine in self._vines.values()
                if vine.state in {VineState.ACTIVE, VineState.TWILIGHT}
                and not vine.locked
            }
            for vine in list(self._vines.values()):
                if vine.state == VineState.EVICTED or vine.locked:
                    continue

                vine.score = live_scores[vine.vine_id]

                # A relevant intent automatically snaps a twilight vine back
                # before its eviction window expires. Requiring a caller to
                # already know the hidden vine id made return-to-topic recall
                # impossible for normal host integrations.
                if (
                    vine.state == VineState.TWILIGHT
                    and vine.score >= TWILIGHT_THRESHOLD
                ):
                    if vine.protected_anchor is None:
                        vine.decompress()
                    vine.state = VineState.ACTIVE
                    vine.twilight_since = None
                    vine.score = min(1.0, vine.score + REINFORCEMENT_BONUS)
                    vine.touch(current_time)
                    self._twilight_cycles.pop(vine.vine_id, None)
                    continue

                if vine.state == VineState.ACTIVE and vine.score < TWILIGHT_THRESHOLD:
                    vine.state = VineState.TWILIGHT
                    vine.twilight_since = current_time
                    if vine.protected_anchor is None:
                        vine.compress()
                    self._twilight_cycles[vine.vine_id] = 0
                    report["demoted"].append(vine.vine_id)

                elif vine.state == VineState.TWILIGHT:
                    if vine.twilight_since is None:
                        vine.twilight_since = current_time
                    self._twilight_cycles.setdefault(vine.vine_id, 0)

                    self._twilight_cycles[vine.vine_id] += 1

                    # Allow caller override for cycle count
                    if vine.vine_id in caller_cycles:
                        self._twilight_cycles[vine.vine_id] = caller_cycles[
                            vine.vine_id
                        ]

                    if self._twilight_expired(vine, current_time):
                        vine.state = VineState.EVICTED
                        report["evicted"].append(vine.vine_id)

            self._enforce_capacity(report)
            return report

    @staticmethod
    def _validate_cycle_overrides(
        cycles: Mapping[str, int] | None,
    ) -> dict[str, int]:
        if cycles is None:
            return {}
        if not isinstance(cycles, Mapping):
            raise TypeError("cycles_since_twilight must be a mapping")
        validated: dict[str, int] = {}
        for vine_id, count in cycles.items():
            if not isinstance(vine_id, str) or not vine_id:
                raise ValueError("cycle override vine ids must be non-empty strings")
            if isinstance(count, bool) or not isinstance(count, int):
                raise TypeError("cycle override counts must be non-negative integers")
            if count < 0:
                raise ValueError("cycle override counts must be non-negative integers")
            validated[vine_id] = count
        return validated

    def _enforce_capacity(self, report: dict[str, list[str]]) -> None:
        live = [v for v in self._vines.values() if v.state != VineState.EVICTED]
        overflow = len(live) - self.config.capacity
        if overflow <= 0:
            return

        candidates = [v for v in live if not v.locked]
        for candidate in candidates:
            if not math.isfinite(candidate.score):
                raise ValueError(f"vine {candidate.vine_id} has a non-finite score")
        candidates.sort(key=lambda vine: (vine.score, vine.last_touched))
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
        with self._lock:
            for vine in self._vines.values():
                if vine.state == VineState.ACTIVE and not vine.locked:
                    vine.score = self._score_active_vine(
                        intent,
                        vine,
                        now,
                        score_fn=score_fn,
                    )

    def _score_active_vine(
        self,
        intent: Vector,
        vine: Vine,
        now: float,
        *,
        score_fn: Callable[[Vector, Vine, float], float] | None = None,
    ) -> float:
        if score_fn is not None:
            score = score_fn(intent, vine, now)
        elif vine.protected_anchor is not None and vine.anchor.shape == (0,):
            score = vine.score
        else:
            anchor = (
                vine.anchor_snapshot()
                if vine.state == VineState.TWILIGHT
                else vine.anchor
            )
            score = proximity_score(
                intent,
                anchor,
                vine.age_hours(now),
                self.config.proximity,
            )
        if isinstance(score, bool) or not isinstance(score, Real):
            raise TypeError("vine scorer must return a finite number")
        result = float(score)
        if not math.isfinite(result):
            raise ValueError("vine scorer must return a finite number")
        return result
