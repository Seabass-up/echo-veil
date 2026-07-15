"""Deterministic random-projection LSH for the durable metadata index.

The index stores only compact hyperplane signatures in SQLite and uses normal
SQLite B-tree indexes to retrieve a candidate set. Candidates are then scored
with the configured (possibly shield-aware) exact scorer. This avoids a global
row scan while keeping the implementation dependency-free and restart-stable.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .vectors import Vector, as_vector, normalize


@dataclass(frozen=True)
class LSHConfig:
    bands: int = 8
    bits_per_band: int = 8
    seed: int = 0xEC40_7E11

    def __post_init__(self) -> None:
        if self.bands <= 0 or self.bits_per_band <= 0:
            raise ValueError("LSH bands and bits_per_band must be positive")
        if self.bits_per_band > 63:
            raise ValueError("LSH bits_per_band must not exceed 63")


class RandomProjectionLSH:
    """Produce stable band signatures for cosine-neighbor candidate lookup."""

    def __init__(self, config: LSHConfig | None = None) -> None:
        self.config = config or LSHConfig()

    def signatures(self, vector: Vector) -> tuple[tuple[int, int], ...]:
        value = normalize(as_vector(vector, allow_empty=False, name="LSH vector"))
        # Dimension is mixed into the seed so every supported dimensionality
        # has a stable, independent family of hyperplanes across restarts.
        seed = (self.config.seed ^ (value.size * 0x9E37_79B1)) & 0xFFFF_FFFF_FFFF_FFFF
        rng = np.random.default_rng(seed)
        planes = rng.standard_normal(
            (self.config.bands, self.config.bits_per_band, value.size),
            dtype=np.float64,
        )
        bits = np.einsum("bij,j->bi", planes, value) >= 0.0
        signatures: list[tuple[int, int]] = []
        for band, band_bits in enumerate(bits):
            bucket = 0
            for offset, bit in enumerate(band_bits):
                if bool(bit):
                    bucket |= 1 << offset
            signatures.append((band, bucket))
        return tuple(signatures)
