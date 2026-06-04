"""Confidence Spectrum Matrix (Section 3).

Maps a retrieval confidence score in [0, 1] to a qualitative band and the
UI/operational behavior the spec prescribes. Thresholds are taken verbatim
from the spec table.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ConfidenceBand(str, Enum):
    SOLID = "solid_vine_integration"
    COHERENT = "coherent_assembly"
    FRAGMENTED = "fragmented_synthesis"
    INFERENTIAL = "high_inferential_leaps"
    OBSCURITY = "data_obscurity_fault"


@dataclass(frozen=True)
class BandPolicy:
    band: ConfidenceBand
    min_score: float
    indicator: str
    behavior: str
    gates_generation: bool  # True => hard stop, do not generate without override


# Ordered high -> low. Thresholds per the spec table.
_POLICIES: tuple[BandPolicy, ...] = (
    BandPolicy(ConfidenceBand.SOLID, 0.85,
               "Solid Vine Integration",
               "Seamless, authoritative delivery.", False),
    BandPolicy(ConfidenceBand.COHERENT, 0.70,
               "Coherent Assembly",
               "Standard delivery; minor context gaps noted in footer.", False),
    BandPolicy(ConfidenceBand.FRAGMENTED, 0.50,
               "Fragmented Synthesis",
               "Micro-Vine Assembly layout; notes inferential leaps.", False),
    BandPolicy(ConfidenceBand.INFERENTIAL, 0.35,
               "High Inferential Leaps",
               "Speculative reconstruction; requires explicit user override.", True),
    BandPolicy(ConfidenceBand.OBSCURITY, 0.0,
               "Data Obscurity Fault",
               "Hard stop. Surface the 3-pronged escalation menu.", True),
)


def classify(score: float) -> BandPolicy:
    """Return the policy for a confidence ``score`` in [0, 1]."""
    if not 0.0 <= score <= 1.0:
        raise ValueError(f"confidence score out of range: {score}")
    for policy in _POLICIES:
        if score >= policy.min_score:
            return policy
    return _POLICIES[-1]  # unreachable; defensive
