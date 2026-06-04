"""Proximity scoring (Section 2, "The Core Decay Loop").

ASSUMPTION (explicit): the source spec references a Proximity Score formula but
the equation itself is missing from the document. We define it here as:

    proximity = cosine_similarity(I, A) * decay(dt)
    decay(dt) = exp(-lambda * dt)

where:
    I       = current intent vector (Seed Crystal Intent Vector)
    A       = the vine's anchor vector
    dt      = hours since the vine was last touched
    lambda  = HALF_LIFE-derived decay constant (configurable)

Rationale for this form:
  - cosine_similarity captures thematic relevance (the spec's primary driver).
  - the exponential time term encodes the spec's "time-decay factor" while
    keeping the score bounded and monotonic in dt.
  - a half-life is more intuitive to tune than a raw lambda, so the config
    exposes half_life_hours and converts internally.

Cosine similarity is in [-1, 1]; we clamp the negative region to 0 before
applying decay so the published score stays in [0, 1], matching the spec's
threshold semantics (0.42 twilight, 0.85 solid integration, etc.).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .vectors import cosine_similarity


@dataclass(frozen=True)
class ProximityConfig:
    half_life_hours: float = 6.0
    """Hours for the time-decay term to halve. Smaller => faster forgetting."""

    @property
    def lambda_(self) -> float:
        # decay(half_life) = 0.5  =>  lambda = ln(2) / half_life
        return math.log(2.0) / self.half_life_hours


def time_decay(age_hours: float, config: ProximityConfig) -> float:
    """Exponential decay term in (0, 1]."""
    age_hours = max(0.0, age_hours)
    return math.exp(-config.lambda_ * age_hours)


def proximity_score(
    intent,
    anchor,
    age_hours: float,
    config: ProximityConfig | None = None,
) -> float:
    """Combined relevance-and-recency score in [0, 1]."""
    cfg = config or ProximityConfig()
    relevance = max(0.0, cosine_similarity(intent, anchor))
    return relevance * time_decay(age_hours, cfg)
