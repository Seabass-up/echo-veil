"""Data Tension Protocol (Section 3): conflicts, fossils, resurrection.

Implements:
  - Peer-Review Zone detection (strength delta <= 0.15) -> Conflict Vine
  - Fossilized Echo: a small (<2KB target) text+metadata summary payload
  - Lazarus Loop: re-sprouting a settled fossil at a neutral 0.55 baseline

The numeric constants (0.15 delta, 2KB cap, 0.55 baseline) are taken verbatim
from the spec.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from numbers import Real

PEER_REVIEW_DELTA = 0.15
FOSSIL_MAX_BYTES = 2048
RESURRECTION_BASELINE = 0.55


def _non_empty_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _strength(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{name} must be a finite value in [0, 1]")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be a finite value in [0, 1]")
    return result


def _timestamp(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{name} must be a finite non-negative timestamp")
    result = float(value)
    if not math.isfinite(result) or result < 0.0:
        raise ValueError(f"{name} must be a finite non-negative timestamp")
    return result


@dataclass
class ConflictVine:
    """Preserves structural tension between two competing claims."""

    topic: str
    claim_a: str
    claim_b: str
    strength_a: float
    strength_b: float
    created_at: float = field(default_factory=time.time)
    resolved: bool = False

    def __post_init__(self) -> None:
        self.topic = _non_empty_text(self.topic, "topic")
        self.claim_a = _non_empty_text(self.claim_a, "claim_a")
        self.claim_b = _non_empty_text(self.claim_b, "claim_b")
        self.strength_a = _strength(self.strength_a, "strength_a")
        self.strength_b = _strength(self.strength_b, "strength_b")
        self.created_at = _timestamp(self.created_at, "created_at")
        if not isinstance(self.resolved, bool):
            raise TypeError("resolved must be a bool")

    @property
    def delta(self) -> float:
        return abs(self.strength_a - self.strength_b)


@dataclass
class FossilizedEcho:
    """A compact, model-agnostic historical record of a settled conflict.

    The spec caps this at <2KB. ``serialize`` enforces that and raises if the
    summary is too large, since silently truncating history would defeat the
    "future-proof record" intent.
    """

    topic: str
    summary: str
    timeline: list[dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        self.topic = _non_empty_text(self.topic, "topic")
        self.summary = _non_empty_text(self.summary, "summary")
        if not isinstance(self.timeline, list) or not all(
            isinstance(event, dict) for event in self.timeline
        ):
            raise TypeError("timeline must be a list of event dictionaries")
        self.timeline = [dict(event) for event in self.timeline]
        self.created_at = _timestamp(self.created_at, "created_at")
        # Fail during construction rather than retaining an invalid artifact.
        self.serialize()

    def record_event(self, event: str, detail: str = "") -> None:
        """Append a mutation to the evolving timeline (re-openings mutate same artifact)."""
        event = _non_empty_text(event, "event")
        if not isinstance(detail, str):
            raise TypeError("detail must be a string")
        entry = {"t": time.time(), "event": event, "detail": detail}
        self.timeline.append(entry)
        try:
            self.serialize()
        except (TypeError, ValueError):
            self.timeline.pop()
            raise

    def approximate_size(self) -> int:
        """Return the current serialized size in bytes without raising.

        Useful for checking how close the fossil is to the 2KB cap before
        calling ``serialize()``, allowing callers to budget timeline entries
        or trim the summary proactively.
        """
        return len(self._payload_bytes())

    def remaining_budget(self) -> int:
        """Return the number of bytes remaining before the 2KB cap.

        Returns a negative number if the fossil is already over cap.
        """
        return FOSSIL_MAX_BYTES - self.approximate_size()

    def serialize(self) -> bytes:
        payload = self._payload_bytes()
        if len(payload) > FOSSIL_MAX_BYTES:
            raise ValueError(
                f"fossil payload {len(payload)}B exceeds {FOSSIL_MAX_BYTES}B cap; "
                "shorten the summary or trim the timeline"
            )
        return payload

    def _payload_bytes(self) -> bytes:
        return json.dumps(
            {
                "topic": self.topic,
                "summary": self.summary,
                "timeline": self.timeline,
                "created_at": self.created_at,
            },
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")


def in_peer_review_zone(strength_a: float, strength_b: float) -> bool:
    """True if two claims are close enough to warrant preserving the tension."""
    validated_a = _strength(strength_a, "strength_a")
    validated_b = _strength(strength_b, "strength_b")
    delta = abs(validated_a - validated_b)
    if math.isclose(delta, PEER_REVIEW_DELTA, abs_tol=1e-9):
        return True
    return delta <= PEER_REVIEW_DELTA


def open_conflict(
    topic: str,
    claim_a: str,
    claim_b: str,
    strength_a: float,
    strength_b: float,
) -> ConflictVine:
    return ConflictVine(topic, claim_a, claim_b, strength_a, strength_b)


def fossilize(conflict: ConflictVine, summary: str) -> FossilizedEcho:
    """Settle a conflict into a fossil once new high-confidence data arrives."""
    if not isinstance(conflict, ConflictVine):
        raise TypeError("conflict must be a ConflictVine")
    if conflict.resolved:
        raise ValueError("conflict is already resolved")
    echo = FossilizedEcho(topic=conflict.topic, summary=summary)
    echo.record_event("fossilized", f"delta={conflict.delta:.3f}")
    # Commit resolution only after the fossil is fully valid and serializable.
    conflict.resolved = True
    return echo


def resurrect(echo: FossilizedEcho) -> ConflictVine:
    """Lazarus Loop: re-sprout a settled fossil at the neutral 0.55 baseline.

    Both sides start at the same baseline so historical inertia cannot bias the
    evaluation of newly arriving data (per the spec).
    """
    if not isinstance(echo, FossilizedEcho):
        raise TypeError("echo must be a FossilizedEcho")
    echo.record_event("resurrected", f"baseline={RESURRECTION_BASELINE}")
    return ConflictVine(
        topic=echo.topic,
        claim_a=f"[historical] {echo.summary}",
        claim_b="[incoming] (pending)",
        strength_a=RESURRECTION_BASELINE,
        strength_b=RESURRECTION_BASELINE,
    )
