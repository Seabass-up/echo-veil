import pytest

from echo_veil.conflict import (
    FOSSIL_MAX_BYTES,
    RESURRECTION_BASELINE,
    fossilize,
    in_peer_review_zone,
    open_conflict,
    resurrect,
)


def test_peer_review_zone_threshold():
    assert in_peer_review_zone(0.80, 0.70) is True   # delta 0.10 <= 0.15
    assert in_peer_review_zone(0.80, 0.60) is False  # delta 0.20 > 0.15


def test_fossilize_marks_resolved_and_records_timeline():
    c = open_conflict("evergy meter", "claim A", "claim B", 0.80, 0.72)
    echo = fossilize(c, summary="A confirmed by inspection.")
    assert c.resolved is True
    assert echo.topic == "evergy meter"
    assert any(e["event"] == "fossilized" for e in echo.timeline)


def test_fossil_size_cap_enforced():
    c = open_conflict("t", "a", "b", 0.5, 0.5)
    with pytest.raises(ValueError):
        fossilize(c, summary="x" * (FOSSIL_MAX_BYTES + 100))


def test_resurrection_uses_neutral_baseline():
    c = open_conflict("t", "a", "b", 0.9, 0.85)
    echo = fossilize(c, summary="settled")
    revived = resurrect(echo)
    assert revived.strength_a == RESURRECTION_BASELINE
    assert revived.strength_b == RESURRECTION_BASELINE
    assert revived.resolved is False
    # Re-opening mutates the SAME fossil artifact (evolving timeline).
    assert any(e["event"] == "resurrected" for e in echo.timeline)
