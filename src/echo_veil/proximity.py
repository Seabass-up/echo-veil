"""Proximity scoring (Section 2, "The Core Decay Loop").

Spec formula (Section 2):

    Proximity Score = cosine_similarity(I, A) + 0.15 * e^(-Δt/12)

where:
    I   = current intent vector (Seed Crystal Intent Vector)
    A   = vine anchor vector
    Δt  = hours since the vine was last touched
    12  = time constant in hours (taken verbatim from the spec)

The 0.15 additive recency term gives a vine a small score from recency alone,
independent of cosine similarity. Score range: (-1, 1.15].
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .vectors import cosine_similarity

RECENCY_WEIGHT = 0.15
TIME_CONSTANT_HOURS = 12.0


@dataclass(frozen=True)
class ProximityConfig:
    time_constant_hours: float = TIME_CONSTANT_HOURS
    """Hours for the recency-decay time constant (spec: 12). Smaller => faster forgetting."""


def time_decay(age_hours: float, config: ProximityConfig) -> float:
    """Recency bonus term: 0.15 * e^(-Δt / time_constant), in (0, 0.15]."""
    age_hours = max(0.0, age_hours)
    return RECENCY_WEIGHT * math.exp(-age_hours / config.time_constant_hours)


def proximity_score(
    intent,
    anchor,
    age_hours: float,
    config: ProximityConfig | None = None,
) -> float:
    """Combined relevance-and-recency score per spec Section 2.

    = cosine_similarity(I, A) + 0.15 * e^(-Δt/12)
    """
    cfg = config or ProximityConfig()
    return cosine_similarity(intent, anchor) + time_decay(age_hours, cfg)
