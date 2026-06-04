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

from dataclasses import dataclass, field

from .vectors import Vector, cosine_similarity


@dataclass
class IndexEntry:
    key: str
    anchor: Vector
    kind: str  # "anchor" | "fossil"


class MetadataIndex:
    """Level 2: semantic lookup over inactive anchors and fossils."""

    def __init__(self) -> None:
        self._entries: dict[str, IndexEntry] = {}

    def upsert(self, key: str, anchor: Vector, kind: str = "anchor") -> None:
        self._entries[key] = IndexEntry(key=key, anchor=anchor, kind=kind)

    def remove(self, key: str) -> None:
        self._entries.pop(key, None)

    def search(self, query: Vector, top_k: int = 5) -> list[tuple[str, float]]:
        """Return up to ``top_k`` (key, similarity) pairs, best first."""
        scored = [
            (e.key, cosine_similarity(query, e.anchor))
            for e in self._entries.values()
        ]
        scored.sort(key=lambda kv: kv[1], reverse=True)
        return scored[:top_k]

    def __len__(self) -> int:
        return len(self._entries)


class ColdArchive:
    """Level 3: raw payload store. Zero active compute (just a dict here)."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}

    def put(self, key: str, payload: bytes) -> None:
        self._store[key] = payload

    def get(self, key: str) -> bytes | None:
        return self._store.get(key)

    def __len__(self) -> int:
        return len(self._store)
