"""The Vine: a single unit of active memory.

Spec mapping (Section 1 / Section 2):
  - "Memory Vine"            -> Vine
  - "Vine Anchor Vector"     -> Vine.anchor
  - lifecycle states         -> VineState

A Vine is deliberately a plain dataclass. All decay/eviction policy lives in
``workspace.py`` so the data model stays inspectable and easy to serialize.
"""

from __future__ import annotations

import time
import uuid
import zlib
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

from .vectors import Vector, as_vector


class VineState(str, Enum):
    """Lifecycle states from the spec's decay loop (Section 2)."""

    ACTIVE = "active"        # Thriving Vine
    TWILIGHT = "twilight"    # compressed, eligible to snap back
    EVICTED = "evicted"      # dissolved from RAM, handed to the archive


@dataclass
class Vine:
    """A single active-memory record.

    Attributes
    ----------
    topic:
        Human-readable label for the conversational thread this vine tracks.
    anchor:
        The vine's anchor vector (768-dim in the spec, any 1-D length here).
    created_at, last_touched:
        Unix timestamps (seconds). ``last_touched`` drives the time-decay term
        of the proximity score.
    state:
        Current lifecycle state.
    locked:
        True if protected by an Amber Lock (immune to proximity decay).
    score:
        Last computed proximity score (cached for reporting / debugging).
    protected_anchor:
        Optional CryptoShield-protected anchor payload. When set, the live
        plaintext ``anchor`` may be released and scoring is delegated to the
        shield by the Oracle.
    _compressed:
        Internal store for the serialized payload when in TWILIGHT.
    _anchor_shape:
        Shape of the anchor array before compression (for decompress restore).
    """

    topic: str
    anchor: Vector
    vine_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)
    last_touched: float = field(default_factory=time.time)
    state: VineState = VineState.ACTIVE
    locked: bool = False
    score: float = 1.0
    twilight_since: float | None = None
    protected_anchor: object | None = field(default=None, repr=False)
    _compressed: bytes | None = field(default=None, repr=False)
    _anchor_shape: tuple[int, ...] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.anchor = as_vector(self.anchor)

    def touch(self, now: float | None = None) -> None:
        """Mark the vine as just-used, resetting its decay clock."""
        self.last_touched = time.time() if now is None else now

    def age_hours(self, now: float | None = None) -> float:
        """Elapsed hours since the vine was last touched."""
        ref = time.time() if now is None else now
        return max(0.0, (ref - self.last_touched) / 3600.0)

    # --- Twilight compression ------------------------------------------------
    # The spec quotes "88% memory footprint compression". Real compression
    # ratios depend on payload entropy, so we compress for real with zlib and
    # report the *achieved* ratio rather than asserting a fixed number. See
    # docs/ARCHITECTURE_NOTES.md (Deviations).

    def compress(self) -> float:
        """Serialize+compress the anchor; return achieved compression ratio.

        The anchor array is zeroed after compression to avoid holding both the
        full array and the compressed bytes in memory simultaneously (the spec
        intends TWILIGHT to reduce, not double, the RAM footprint).
        """
        raw = self.anchor.astype(np.float64).tobytes()
        self._compressed = zlib.compress(raw, level=9)
        self._anchor_shape = self.anchor.shape
        self.anchor = np.zeros(0)  # release the live array
        if not raw:
            return 0.0
        return 1.0 - (len(self._compressed) / len(raw))

    def decompress(self) -> None:
        """Restore the anchor from its compressed form (snap-back).

        Reconstructs the full-dimension anchor array and releases the
        compressed bytes.
        """
        if self._compressed is None:
            return
        raw = zlib.decompress(self._compressed)
        restored = np.frombuffer(raw, dtype=np.float64).copy()
        if self._anchor_shape is not None and self._anchor_shape != (0,):
            restored = restored.reshape(self._anchor_shape)
        self.anchor = restored
        self._compressed = None
        self._anchor_shape = None

    def archive_payload(self) -> bytes | None:
        """Return the compressed anchor bytes for L3 cold archive storage.

        Available when the vine is in TWILIGHT or EVICTED state (after
        compress() has been called). Returns None if no compressed data exists.
        """
        return self._compressed