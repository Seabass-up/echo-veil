"""Tiered storage backends (Sections 1.2 and 1.3).

This module provides an in-memory *reference* implementation of the two lower
tiers so the lifecycle logic is testable end-to-end without external
infrastructure:

  - MetadataIndex  -> Level 2 "Latent Spore Network": a sparse vector index for
    semantic lookup of inactive anchors and fossils.
  - ColdArchive    -> Level 3 "Deep Soil": raw payload store, zero active
    compute, accessed only on escalation.

These are intentionally simple (linear scan, dict store). The interfaces are
the contract; a production deployment would swap in a real ANN index (e.g.
FAISS / a vector DB) and an object store. See docs/ARCHITECTURE_NOTES.md.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from numbers import Real
from threading import RLock
from typing import Any, Protocol, TypeGuard

from .vectors import Vector, as_vector, cosine_similarity

INDEX_KINDS = frozenset({"anchor", "fossil", "protected_anchor"})


@dataclass(frozen=True)
class EvictionRecord:
    """One atomic L1 -> L2/L3 transfer prepared by the Oracle."""

    key: str
    anchor: Any
    kind: str
    archive_payload: bytes
    dimension: int
    metadata: Mapping[str, object] = field(default_factory=dict)
    index_hint: Vector | None = None


class MetadataIndexBackend(Protocol):
    """Storage-agnostic L2 index contract consumed by the Oracle."""

    backend_name: str
    durable: bool
    transactional: bool
    cross_process_safe: bool
    search_strategy: str

    @property
    def dimension(self) -> int | None:
        raise NotImplementedError

    def upsert(self, key: str, anchor: Any, kind: str = "anchor") -> None:
        raise NotImplementedError

    def remove(self, key: str) -> None:
        raise NotImplementedError

    def search(
        self,
        query: Vector,
        top_k: int = 5,
        score_fn: Callable[[Vector, IndexEntry], float] | None = None,
    ) -> list[tuple[str, float]]:
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError


class ArchiveBackend(Protocol):
    """Storage-agnostic L3 archive contract consumed by the Oracle."""

    backend_name: str
    durable: bool
    transactional: bool
    cross_process_safe: bool

    def put(self, key: str, payload: bytes) -> None:
        raise NotImplementedError

    def get(self, key: str) -> bytes | None:
        raise NotImplementedError

    def __len__(self) -> int:
        raise NotImplementedError


class TransactionalEvictionStore(Protocol):
    """Coordinates durable writes across the active workspace and lower tiers."""

    index: MetadataIndexBackend
    archive: ArchiveBackend
    backend_name: str
    durable: bool
    transactional: bool
    cross_process_safe: bool

    def commit_evictions(self, records: list[EvictionRecord]) -> None:
        raise NotImplementedError

    def save_workspace(
        self,
        vines: list[Any],
        twilight_cycles: Mapping[str, int],
        crests: tuple[str, ...],
    ) -> None:
        raise NotImplementedError

    def load_workspace(self) -> tuple[list[Any], dict[str, int], tuple[str, ...]]:
        raise NotImplementedError


def is_transactional_eviction_store(
    candidate: object,
) -> TypeGuard[TransactionalEvictionStore]:
    """Structurally validate a coordinated storage backend."""
    index = getattr(candidate, "index", None)
    archive = getattr(candidate, "archive", None)
    return (
        callable(getattr(candidate, "commit_evictions", None))
        and callable(getattr(candidate, "save_workspace", None))
        and callable(getattr(candidate, "load_workspace", None))
        and callable(getattr(index, "upsert", None))
        and callable(getattr(index, "search", None))
        and callable(getattr(archive, "put", None))
        and callable(getattr(archive, "get", None))
    )


@dataclass(frozen=True)
class IndexEntry:
    key: str
    anchor: Any
    kind: str  # "anchor" | "fossil" | "protected_anchor"


class MetadataIndex:
    """Level 2: semantic lookup over inactive anchors and fossils."""

    backend_name = "in-memory metadata index"
    durable = False
    transactional = False
    cross_process_safe = False
    search_strategy = "linear"

    def __init__(self) -> None:
        self._entries: dict[str, IndexEntry] = {}
        self._dimension: int | None = None
        self._lock = RLock()

    def upsert(self, key: str, anchor: Any, kind: str = "anchor") -> None:
        self._validate_key(key)
        if kind not in INDEX_KINDS:
            raise ValueError(f"unsupported index entry kind: {kind!r}")

        stored_anchor = anchor
        dimension: int | None = None
        if kind in {"anchor", "fossil"}:
            stored_anchor = as_vector(
                anchor,
                allow_empty=False,
                copy=True,
                name="index anchor",
            )
            dimension = stored_anchor.size
        else:
            shape = getattr(anchor, "shape", None)
            if (
                isinstance(shape, tuple)
                and len(shape) == 1
                and isinstance(shape[0], int)
                and not isinstance(shape[0], bool)
                and shape[0] > 0
            ):
                dimension = shape[0]

        with self._lock:
            if dimension is not None:
                if self._dimension is None:
                    self._dimension = dimension
                elif dimension != self._dimension:
                    raise ValueError(
                        f"dimension mismatch: expected ({self._dimension},), "
                        f"got ({dimension},)"
                    )
            self._entries[key] = IndexEntry(
                key=key,
                anchor=stored_anchor,
                kind=kind,
            )

    def remove(self, key: str) -> None:
        self._validate_key(key)
        with self._lock:
            self._entries.pop(key, None)

    def search(
        self,
        query: Vector,
        top_k: int = 5,
        score_fn: Callable[[Vector, IndexEntry], float] | None = None,
    ) -> list[tuple[str, float]]:
        """Return up to ``top_k`` (key, similarity) pairs, best first."""
        if isinstance(top_k, bool) or not isinstance(top_k, int):
            raise TypeError("top_k must be a non-negative integer")
        if top_k < 0:
            raise ValueError("top_k must be a non-negative integer")
        query_vector = as_vector(
            query,
            allow_empty=False,
            name="query vector",
        )
        with self._lock:
            if self._dimension is not None and query_vector.size != self._dimension:
                raise ValueError(
                    f"dimension mismatch: expected ({self._dimension},), "
                    f"got {query_vector.shape}"
                )
            entries = list(self._entries.values())

        if score_fn is None and any(
            entry.kind == "protected_anchor" for entry in entries
        ):
            raise TypeError("protected index entries require a shield-aware score_fn")

        scored: list[tuple[str, float]] = []
        for entry in entries:
            raw_score = (
                score_fn(query_vector, entry)
                if score_fn is not None
                else cosine_similarity(query_vector, entry.anchor)
            )
            if isinstance(raw_score, bool) or not isinstance(raw_score, Real):
                raise TypeError("index scorer must return a finite number")
            score = float(raw_score)
            if not math.isfinite(score):
                raise ValueError("index scorer must return a finite number")
            scored.append((entry.key, score))
        scored.sort(key=lambda kv: kv[1], reverse=True)
        return scored[:top_k]

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def dimension(self) -> int | None:
        with self._lock:
            return self._dimension

    @staticmethod
    def _validate_key(key: str) -> None:
        if not isinstance(key, str) or not key.strip():
            raise ValueError("archive/index keys must be non-empty strings")


class ColdArchive:
    """Level 3: raw payload store. Zero active compute (just a dict here)."""

    backend_name = "in-memory cold archive"
    durable = False
    transactional = False
    cross_process_safe = False

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._lock = RLock()

    def put(self, key: str, payload: bytes) -> None:
        MetadataIndex._validate_key(key)
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("archive payload must be bytes-like")
        stored = bytes(payload)
        if not stored:
            raise ValueError("archive payload must not be empty")
        with self._lock:
            self._store[key] = stored

    def get(self, key: str) -> bytes | None:
        MetadataIndex._validate_key(key)
        with self._lock:
            return self._store.get(key)

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)
