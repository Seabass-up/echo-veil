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
from numbers import Real

from .vectors import cosine_similarity

RECENCY_WEIGHT = 0.15
TIME_CONSTANT_HOURS = 12.0


@dataclass(frozen=True)
class ProximityConfig:
    time_constant_hours: float = TIME_CONSTANT_HOURS
    """Hours for the recency-decay time constant (spec: 12). Smaller => faster forgetting."""

    def __post_init__(self) -> None:
        if isinstance(self.time_constant_hours, bool) or not isinstance(
            self.time_constant_hours, Real
        ):
            raise TypeError("time_constant_hours must be a finite positive number")
        value = float(self.time_constant_hours)
        if not math.isfinite(value) or value <= 0.0:
            raise ValueError("time_constant_hours must be a finite positive number")
        object.__setattr__(self, "time_constant_hours", value)


def time_decay(age_hours: float, config: ProximityConfig) -> float:
    """Recency bonus term: 0.15 * e^(-Δt / time_constant), in (0, 0.15]."""
    if not isinstance(config, ProximityConfig):
        raise TypeError("config must be a ProximityConfig")
    if isinstance(age_hours, bool) or not isinstance(age_hours, Real):
        raise TypeError("age_hours must be a finite number")
    age_hours = float(age_hours)
    if not math.isfinite(age_hours):
        raise ValueError("age_hours must be finite")
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
    cfg = ProximityConfig() if config is None else config
    if not isinstance(cfg, ProximityConfig):
        raise TypeError("config must be a ProximityConfig")
    return cosine_similarity(intent, anchor) + time_decay(age_hours, cfg)
