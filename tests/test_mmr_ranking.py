"""MMR ordering must stay exact while each eligible vector pair is compared once."""

from dataclasses import replace

import numpy as np
import pytest

from echo_veil import agent_memory as memory


def _reference_rank(candidates):
    remaining = list(candidates)
    selected = []
    while remaining:

        def selection_key(candidate):
            diversity = 0.0
            if candidate.best_vector is not None:
                similarities = [
                    memory.cosine_similarity(candidate.best_vector, prior.best_vector)
                    for prior in selected
                    if prior.best_vector is not None
                    and prior.topic.casefold() != candidate.topic.casefold()
                ]
                diversity = max(similarities, default=0.0)
            mmr = memory.MMR_RELEVANCE_WEIGHT * candidate.relevance_score - (
                1.0 - memory.MMR_RELEVANCE_WEIGHT
            ) * max(0.0, diversity)
            return (1 if candidate.temporal_current else 0, mmr, candidate.effective_at)

        winner = max(remaining, key=selection_key)
        selected.append(winner)
        remaining.remove(winner)
    return selected


def _candidate(
    index, vector, *, topic=None, relevance=0.5, current=True, effective_at=1.0
):
    return memory._RankedCandidate(
        vine_id=f"fixture-{index}",
        topic=f"topic-{index}" if topic is None else topic,
        source="archive",
        relevance_score=relevance,
        semantic_score=relevance,
        answerability_score=0.8,
        lexical_score=0.0,
        lifecycle_score=None,
        best_vector=vector,
        effective_at=effective_at,
        superseded_by=None if current else "newer-fixture",
        superseded_at=None if current else effective_at + 1.0,
        temporal_current=current,
    )


def _assert_same(candidates):
    before_ids = [id(candidate) for candidate in candidates]
    before_vectors = [
        None if candidate.best_vector is None else candidate.best_vector.copy()
        for candidate in candidates
    ]
    expected = _reference_rank(candidates)
    actual = memory._mmr_rank(candidates)
    assert [id(candidate) for candidate in actual] == [
        id(candidate) for candidate in expected
    ]
    assert [id(candidate) for candidate in candidates] == before_ids
    for candidate, vector in zip(candidates, before_vectors, strict=True):
        if vector is not None:
            np.testing.assert_array_equal(candidate.best_vector, vector)


@pytest.mark.parametrize("seed", range(24))
def test_mmr_matches_reference_on_mixed_candidates(seed):
    rng = np.random.default_rng(seed)
    for count in (0, 1, 2, 8, 24):
        candidates = []
        for index in range(count):
            vector = rng.normal(size=16)
            vector /= np.linalg.norm(vector)
            candidates.append(
                _candidate(
                    index,
                    None if (seed + index) % 7 == 0 else vector,
                    topic=("same", "SAME", "Stra\u00dfe", "STRASSE", f"unique-{index}")[
                        (seed + index) % 5
                    ],
                    relevance=float(rng.choice([0.0, 0.25, 0.5, 0.75, 1.0]))
                    if seed % 2
                    else float(rng.random()),
                    current=bool(rng.integers(2)),
                    effective_at=float(rng.integers(5)),
                )
            )
        _assert_same(candidates)


@pytest.mark.parametrize(
    "vectors",
    [
        [None, None, None],
        [np.zeros(3), np.ones(3), -np.ones(3)],
        [np.ones(3), np.ones(3), np.ones(3)],
        [np.array([1.0, 0.0]), np.array([-1.0, 0.0]), np.array([0.0, 1.0])],
        [np.array([1e308, 1e308]), np.array([1e308, -1e308]), np.ones(2)],
    ],
)
def test_mmr_preserves_ties_zero_vectors_and_max_fold(vectors):
    with np.errstate(over="ignore", invalid="ignore"):
        _assert_same(
            [_candidate(index, vector) for index, vector in enumerate(vectors)]
        )


def test_mmr_prioritizes_current_then_effective_time_and_input_order():
    candidates = [
        _candidate(0, None, relevance=1.0, current=False),
        _candidate(1, None, relevance=0.0, effective_at=0.0),
        _candidate(2, None, relevance=0.0, effective_at=2.0),
        _candidate(3, None, relevance=0.0, effective_at=2.0),
    ]
    assert [item.vine_id for item in memory._mmr_rank(candidates)] == [
        "fixture-2",
        "fixture-3",
        "fixture-1",
        "fixture-0",
    ]


@pytest.mark.parametrize("count", [0, 1, 2, 8, 32, 64])
def test_mmr_compares_each_pair_at_most_once(monkeypatch, count):
    calls = []
    cosine = memory.cosine_similarity

    def observed(left, right):
        calls.append((id(left), id(right)))
        return cosine(left, right)

    monkeypatch.setattr(memory, "cosine_similarity", observed)
    candidates = [
        _candidate(index, np.array([1.0, float(index)])) for index in range(count)
    ]
    assert len(memory._mmr_rank(candidates)) == count
    assert len(calls) == len(set(calls)) == count * (count - 1) // 2


def test_mmr_does_not_compare_same_topic_or_missing_vectors(monkeypatch):
    def forbidden(*_args):
        raise AssertionError("these candidates have no eligible vector pair")

    monkeypatch.setattr(memory, "cosine_similarity", forbidden)
    candidates = [
        _candidate(index, np.ones(4), topic="same" if index % 2 else "SAME")
        for index in range(8)
    ]
    candidates.extend(_candidate(index + 8, None) for index in range(4))
    _assert_same(candidates)


@pytest.mark.parametrize(
    "bad_vector",
    [np.array([]), np.array([np.nan]), np.array([np.inf]), np.ones((2, 2)), np.ones(5)],
)
def test_mmr_retains_vector_error_boundaries(bad_vector):
    candidates = [_candidate(0, np.ones(4), relevance=1.0), _candidate(1, bad_vector)]
    with pytest.raises(ValueError) as before:
        _reference_rank(candidates)
    with pytest.raises(ValueError) as after:
        memory._mmr_rank(candidates)
    assert str(after.value) == str(before.value)


def test_mmr_is_fresh_after_relevance_and_vector_changes():
    candidates = [
        _candidate(0, np.array([1.0, 0.0]), relevance=0.9),
        _candidate(1, np.array([0.0, 1.0])),
    ]
    _assert_same(candidates)
    candidates = [
        replace(candidates[0], relevance_score=0.1),
        replace(candidates[1], best_vector=np.array([1.0, 0.0])),
    ]
    _assert_same(candidates)
