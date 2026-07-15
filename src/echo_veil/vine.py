"""The Vine: a single unit of active memory.

Spec mapping (Section 1 / Section 2):
  - "Memory Vine"            -> Vine
  - "Vine Anchor Vector"     -> Vine.anchor
  - lifecycle states         -> VineState

A Vine is deliberately a plain dataclass. All decay/eviction policy lives in
``workspace.py`` so the data model stays inspectable and easy to serialize.
"""

from __future__ import annotations

import math
import time
import uuid
import zlib
from dataclasses import dataclass, field
from enum import Enum
from numbers import Real

import numpy as np

from .vectors import Vector, as_vector


class VineState(str, Enum):
    """Lifecycle states from the spec's decay loop (Section 2)."""

    ACTIVE = "active"  # Thriving Vine
    TWILIGHT = "twilight"  # compressed, eligible to snap back
    EVICTED = "evicted"  # dissolved from RAM, handed to the archive


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
        if not isinstance(self.topic, str) or not self.topic.strip():
            raise ValueError("topic must be a non-empty string")
        if not isinstance(self.vine_id, str) or not self.vine_id.strip():
            raise ValueError("vine_id must be a non-empty string")
        self.state = VineState(self.state)
        self.created_at = self._validate_timestamp(self.created_at, "created_at")
        self.last_touched = self._validate_timestamp(self.last_touched, "last_touched")
        if self.twilight_since is not None:
            self.twilight_since = self._validate_timestamp(
                self.twilight_since,
                "twilight_since",
            )
        if isinstance(self.score, bool) or not isinstance(self.score, Real):
            raise TypeError("score must be finite")
        self.score = float(self.score)
        if not math.isfinite(self.score):
            raise ValueError("score must be finite")
        self.anchor = as_vector(
            self.anchor,
            allow_empty=self.protected_anchor is not None,
            copy=True,
            name="anchor vector",
        )

    @staticmethod
    def _validate_timestamp(value: float, name: str) -> float:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise TypeError(f"{name} must be a finite non-negative timestamp")
        result = float(value)
        if not math.isfinite(result) or result < 0.0:
            raise ValueError(f"{name} must be a finite non-negative timestamp")
        return result

    def touch(self, now: float | None = None) -> None:
        """Mark the vine as just-used, resetting its decay clock."""
        value = time.time() if now is None else now
        self.last_touched = self._validate_timestamp(value, "now")

    def age_hours(self, now: float | None = None) -> float:
        """Elapsed hours since the vine was last touched."""
        value = time.time() if now is None else now
        ref = self._validate_timestamp(value, "now")
        last_touched = self._validate_timestamp(self.last_touched, "last_touched")
        return max(0.0, (ref - last_touched) / 3600.0)

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
        if self.anchor.size == 0:
            raise ValueError("cannot compress an empty anchor vector")
        raw = self.anchor.astype(np.float64, copy=False).tobytes(order="C")
        self._compressed = zlib.compress(raw, level=9)
        self._anchor_shape = self.anchor.shape
        self.anchor = np.zeros(0, dtype=np.float64)  # release the live array
        return 1.0 - (len(self._compressed) / len(raw))

    def anchor_snapshot(self) -> Vector:
        """Return a validated copy of the anchor without changing lifecycle state.

        For TWILIGHT/EVICTED vines this performs bounded decompression into a
        temporary array. It lets the Oracle build L2 metadata without restoring
        plaintext onto an externally referenced evicted Vine object.
        """
        if self._compressed is None:
            return as_vector(
                self.anchor,
                allow_empty=False,
                copy=True,
                name="anchor vector",
            )
        if (
            self._anchor_shape is None
            or len(self._anchor_shape) != 1
            or isinstance(self._anchor_shape[0], bool)
            or not isinstance(self._anchor_shape[0], int)
            or self._anchor_shape[0] <= 0
        ):
            raise ValueError("compressed anchor has invalid shape metadata")

        expected_bytes = self._anchor_shape[0] * np.dtype(np.float64).itemsize
        decompressor = zlib.decompressobj()
        try:
            raw = decompressor.decompress(self._compressed, expected_bytes + 1)
        except zlib.error as exc:
            raise ValueError("compressed anchor payload is corrupt") from exc
        if (
            len(raw) != expected_bytes
            or not decompressor.eof
            or decompressor.unconsumed_tail
            or decompressor.unused_data
        ):
            raise ValueError("compressed anchor payload does not match shape metadata")
        restored = np.frombuffer(raw, dtype=np.float64).reshape(self._anchor_shape)
        return as_vector(
            restored,
            allow_empty=False,
            copy=True,
            name="decompressed anchor vector",
        )

    def decompress(self) -> None:
        """Restore the anchor from its compressed form (snap-back).

        Reconstructs the full-dimension anchor array and releases the
        compressed bytes.
        """
        if self._compressed is None:
            return
        self.anchor = self.anchor_snapshot()
        self._compressed = None
        self._anchor_shape = None

    def archive_payload(self) -> bytes | None:
        """Return the compressed anchor bytes for L3 cold archive storage.

        Available when the vine is in TWILIGHT or EVICTED state (after
        compress() has been called). Returns None if no compressed data exists.
        """
        return self._compressed
