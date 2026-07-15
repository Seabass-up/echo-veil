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
from threading import RLock

from .vectors import Vector, as_vector, centroid, cosine_similarity

WINDOW = 3
DRIFT_THRESHOLD = 0.38
HYSTERESIS = 0.08


class DriftDetector:
    """Tracks recent intents and flags sustained topic drift."""

    def __init__(self, window: int = WINDOW) -> None:
        if isinstance(window, bool) or not isinstance(window, int):
            raise TypeError("window must be a positive integer")
        if window <= 0:
            raise ValueError("window must be a positive integer")
        self._recent: deque[Vector] = deque(maxlen=window)
        self._drifting = False  # current latched state, for hysteresis
        self._dimension: int | None = None
        self._lock = RLock()

    def observe(self, intent: Vector) -> None:
        vector = as_vector(
            intent,
            allow_empty=False,
            copy=True,
            name="intent vector",
        )
        with self._lock:
            if self._dimension is None:
                self._dimension = vector.size
            elif vector.size != self._dimension:
                raise ValueError(
                    f"dimension mismatch: expected ({self._dimension},), got {vector.shape}"
                )
            self._recent.append(vector)

    def moving_average(self) -> Vector | None:
        with self._lock:
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
        with self._lock:
            d = self.drift(garden_centroid)
            if self._drifting:
                if d < DRIFT_THRESHOLD - HYSTERESIS:
                    self._drifting = False
            elif d > DRIFT_THRESHOLD + HYSTERESIS:
                self._drifting = True
            return self._drifting

    def reset(self) -> None:
        """Clear all observed intents and the latched drift state.

        Useful for session resets, test teardown, or when the conversation
        context changes so radically that prior drift measurements are
        no longer meaningful.
        """
        with self._lock:
            self._recent.clear()
            self._drifting = False
            self._dimension = None
