#!/usr/bin/env python3
"""Small, deterministic application-agent integration example.

The vocabulary embedder is intentionally a local teaching aid, not a production
embedding model. Run with: ``uv run python examples/agent_memory.py``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass

import numpy as np
from numpy.typing import NDArray

from echo_veil import Oracle, WorkspaceConfig


VOCABULARY = (
    "estimate",
    "labor",
    "rate",
    "service",
    "school",
    "pickup",
    "schedule",
    "family",
)


def demo_embedding(text: str) -> NDArray[np.float64]:
    """Return a normalized bag-of-words vector for the fixed demo vocabulary."""
    words = set(re.findall(r"[a-z]+", text.lower()))
    vector = np.array([float(token in words) for token in VOCABULARY])
    magnitude = float(np.linalg.norm(vector))
    if magnitude == 0.0:
        raise ValueError("demo text must contain a vocabulary term")
    return vector / magnitude


@dataclass(frozen=True)
class RecallResult:
    vine_id: str
    topic: str
    payload: str
    score: float
    confidence_band: str
    confidence_indicator: str


class ApplicationMemory:
    """Minimal host adapter that keeps payload authorization outside Echo Veil."""

    def __init__(self, embed: Callable[[str], NDArray[np.float64]]) -> None:
        self._embed = embed
        self._oracle = Oracle(
            WorkspaceConfig(capacity=8, pressure_evict_at=0.0),
            environment="development",
        )
        self._authorized_payloads: dict[str, str] = {}

    def remember(self, topic: str, payload: str) -> str:
        vine = self._oracle.sprout(topic, self._embed(f"{topic} {payload}"))
        self._authorized_payloads[vine.vine_id] = payload
        return vine.vine_id

    def recall(self, query: str) -> RecallResult | None:
        """Observe one turn, rank active vines, and enforce generation policy."""
        self._oracle.observe(self._embed(query))
        candidates = sorted(
            self._oracle.workspace.active(),
            key=lambda vine: vine.score,
            reverse=True,
        )
        if not candidates:
            return None
        candidate = candidates[0]
        policy = self._oracle.check_generation_gate(candidate.score)
        return RecallResult(
            vine_id=candidate.vine_id,
            topic=candidate.topic,
            payload=self._authorized_payloads[candidate.vine_id],
            score=round(candidate.score, 6),
            confidence_band=policy.band.value,
            confidence_indicator=policy.indicator,
        )


def run_demo() -> RecallResult:
    memory = ApplicationMemory(demo_embedding)
    memory.remember(
        "Topping Avenue service estimate labor rate",
        "The approved labor rate is 125 dollars per hour.",
    )
    memory.remember(
        "Family school pickup schedule",
        "School pickup is at 3 PM.",
    )
    result = memory.recall("What labor rate was used for the service estimate?")
    if result is None:
        raise RuntimeError("the demonstration did not retrieve an active memory")
    return result


def main() -> int:
    print(json.dumps(asdict(run_demo()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
