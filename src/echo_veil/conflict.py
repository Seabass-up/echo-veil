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
import time
from dataclasses import dataclass, field

PEER_REVIEW_DELTA = 0.15
FOSSIL_MAX_BYTES = 2048
RESURRECTION_BASELINE = 0.55


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

    def record_event(self, event: str, detail: str = "") -> None:
        """Append a mutation to the evolving timeline (re-openings mutate same artifact)."""
        self.timeline.append(
            {"t": time.time(), "event": event, "detail": detail}
        )

    def serialize(self) -> bytes:
        payload = json.dumps(
            {
                "topic": self.topic,
                "summary": self.summary,
                "timeline": self.timeline,
                "created_at": self.created_at,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > FOSSIL_MAX_BYTES:
            raise ValueError(
                f"fossil payload {len(payload)}B exceeds {FOSSIL_MAX_BYTES}B cap; "
                "shorten the summary or trim the timeline"
            )
        return payload


def in_peer_review_zone(strength_a: float, strength_b: float) -> bool:
    """True if two claims are close enough to warrant preserving the tension."""
    return abs(strength_a - strength_b) <= PEER_REVIEW_DELTA


def open_conflict(topic, claim_a, claim_b, strength_a, strength_b) -> ConflictVine:
    return ConflictVine(topic, claim_a, claim_b, strength_a, strength_b)


def fossilize(conflict: ConflictVine, summary: str) -> FossilizedEcho:
    """Settle a conflict into a fossil once new high-confidence data arrives."""
    conflict.resolved = True
    echo = FossilizedEcho(topic=conflict.topic, summary=summary)
    echo.record_event("fossilized", f"delta={conflict.delta:.3f}")
    # Validate size up front so callers fail fast.
    echo.serialize()
    return echo


def resurrect(echo: FossilizedEcho) -> ConflictVine:
    """Lazarus Loop: re-sprout a settled fossil at the neutral 0.55 baseline.

    Both sides start at the same baseline so historical inertia cannot bias the
    evaluation of newly arriving data (per the spec).
    """
    echo.record_event("resurrected", f"baseline={RESURRECTION_BASELINE}")
    return ConflictVine(
        topic=echo.topic,
        claim_a=f"[historical] {echo.summary}",
        claim_b="[incoming] (pending)",
        strength_a=RESURRECTION_BASELINE,
        strength_b=RESURRECTION_BASELINE,
    )
