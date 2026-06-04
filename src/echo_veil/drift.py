"""Intent Drift Detection Engine (Section 4).

Measures conversational drift against a moving average of recent intents,
compared to the established centroid of the active garden, rather than reacting
to single-prompt deltas. A hysteresis buffer prevents jittery false alarms.

Constants from the spec:
  WINDOW              = 3      (3-query moving average)
  DRIFT_THRESHOLD     = 0.38
  HYSTERESIS          = 0.08
"""

from __future__ import annotations

from collections import deque

import numpy as np

from .vectors import Vector, as_vector, centroid, cosine_similarity

WINDOW = 3
DRIFT_THRESHOLD = 0.38
HYSTERESIS = 0.08


class DriftDetector:
    """Tracks recent intents and flags sustained topic drift."""

    def __init__(self, window: int = WINDOW) -> None:
        self._recent: deque[Vector] = deque(maxlen=window)
        self._drifting = False  # current latched state, for hysteresis

    def observe(self, intent: Vector) -> None:
        self._recent.append(as_vector(intent))

    def moving_average(self) -> Vector | None:
        if not self._recent:
            return None
        return centroid(list(self._recent))

    def drift(self, garden_centroid: Vector) -> float:
        """Drift magnitude in [0, 2]: 1 - cosine(avg_intent, garden_centroid).

        0 == perfectly aligned, 1 == orthogonal, 2 == opposed.
        """
        avg = self.moving_average()
        if avg is None:
            return 0.0
        return 1.0 - cosine_similarity(avg, garden_centroid)

    def is_drifting(self, garden_centroid: Vector) -> bool:
        """Hysteresis-buffered drift flag.

        Crosses into "drifting" only above DRIFT_THRESHOLD + HYSTERESIS, and
        back out only below DRIFT_THRESHOLD - HYSTERESIS. The dead band keeps
        isolated sidebar questions from toggling the alarm.
        """
        d = self.drift(garden_centroid)
        if self._drifting:
            if d < DRIFT_THRESHOLD - HYSTERESIS:
                self._drifting = False
        else:
            if d > DRIFT_THRESHOLD + HYSTERESIS:
                self._drifting = True
        return self._drifting
