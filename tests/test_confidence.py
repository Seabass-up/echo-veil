import pytest

from echo_veil.confidence import ConfidenceBand, classify


@pytest.mark.parametrize(
    "score,band,gates",
    [
        (0.95, ConfidenceBand.SOLID, False),
        (0.85, ConfidenceBand.SOLID, False),
        (0.80, ConfidenceBand.COHERENT, False),
        (0.70, ConfidenceBand.COHERENT, False),
        (0.60, ConfidenceBand.FRAGMENTED, False),
        (0.50, ConfidenceBand.FRAGMENTED, False),
        (0.40, ConfidenceBand.INFERENTIAL, True),
        (0.35, ConfidenceBand.INFERENTIAL, True),
        (0.20, ConfidenceBand.OBSCURITY, True),
        (0.0, ConfidenceBand.OBSCURITY, True),
    ],
)
def test_classification_boundaries(score, band, gates):
    policy = classify(score)
    assert policy.band == band
    assert policy.gates_generation == gates


def test_out_of_range_rejected():
    with pytest.raises(ValueError):
        classify(1.5)
    with pytest.raises(ValueError):
        classify(-0.1)
