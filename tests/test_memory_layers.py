from __future__ import annotations

import json

import pytest

from echo_veil.memory_layers import (
    LogicKind,
    MemoryLayer,
    MemoryLayerContract,
    new_memory_contract,
)


def test_new_memory_defaults_to_reviewable_short_term() -> None:
    contract = new_memory_contract(now=1_000.0)

    assert contract.layer == MemoryLayer.SHORT_TERM
    assert contract.provenance == ("caller:unspecified",)
    assert contract.review_at == 1_000.0 + 7 * 24 * 60 * 60
    assert contract.expires_at is None
    assert contract.recommendations(now=1_001.0) == {
        "promotion": "retain_short_term_until_review",
        "archive": "archive_or_discard_if_no_longer_actionable",
    }


def test_live_memory_is_bounded_and_never_implicitly_archived() -> None:
    contract = new_memory_contract(
        "live",
        provenance=["agent:turn-7"],
        now=1_000.0,
    )

    assert contract.layer == MemoryLayer.LIVE
    assert contract.expires_at == 2_800.0
    assert contract.is_expired(now=2_799.0) is False
    assert contract.is_expired(now=2_800.0) is True
    assert contract.recommendations(now=2_800.0)["archive"] == (
        "do_not_archive_live_memory_expired"
    )

    with pytest.raises(ValueError, match="within 24 hours"):
        new_memory_contract("live", expires_at=100_000.0, now=1_000.0)


def test_live_contract_refresh_renews_expiry_and_merges_provenance() -> None:
    live = new_memory_contract(
        "live",
        provenance=["agent:turn-7"],
        now=1_000.0,
    )
    refreshed = live.refresh_live(
        provenance=["tool:latest-result"],
        expires_at=3_000.0,
        now=1_100.0,
    )

    assert refreshed.layer == MemoryLayer.LIVE
    assert refreshed.expires_at == 3_000.0
    assert refreshed.provenance == ("agent:turn-7", "tool:latest-result")
    assert live.expires_at == 2_800.0

    with pytest.raises(ValueError, match="only live"):
        new_memory_contract(now=1_000.0).refresh_live(now=1_100.0)


def test_contextual_logic_requires_explicit_provenance_and_reason() -> None:
    kwargs: dict[str, object] = {
        "logic_kind": "decision",
        "related_ids": ["a" * 32],
    }
    with pytest.raises(ValueError, match="explicit provenance"):
        new_memory_contract(
            "contextual_logic",
            promotion_reason="Reviewed.",
            **kwargs,
        )
    with pytest.raises((TypeError, ValueError), match="promotion reason"):
        new_memory_contract(
            "contextual_logic",
            provenance=["source:reviewed"],
            **kwargs,
        )
    with pytest.raises(ValueError, match="non-caller evidence"):
        new_memory_contract(
            "contextual_logic",
            provenance=["caller:codex"],
            promotion_reason="Reviewed.",
            **kwargs,
        )


def test_long_term_requires_ordered_promotion() -> None:
    with pytest.raises(ValueError, match="must be promoted"):
        new_memory_contract(
            "long_term",
            provenance=["source:reviewed"],
            promotion_reason="Reviewed.",
        )


def test_long_term_promotion_requires_durable_provenance() -> None:
    short = new_memory_contract(now=1_000.0)

    with pytest.raises(ValueError, match="durable provenance"):
        short.promote(
            "long_term",
            reason="The fact was reviewed.",
            now=1_100.0,
        )
    caller_attributed = new_memory_contract(
        provenance=["caller:codex"],
        now=1_000.0,
    )
    with pytest.raises(ValueError, match="durable provenance"):
        caller_attributed.promote(
            "long_term",
            reason="Transport identity is not durable evidence.",
            now=1_100.0,
        )

    promoted = short.promote(
        "long_term",
        reason="The fact was reviewed.",
        provenance=["user:explicit-confirmation"],
        now=1_100.0,
    )
    assert promoted.provenance == (
        "caller:unspecified",
        "user:explicit-confirmation",
    )


def test_contextual_logic_round_trip_preserves_typed_relationships() -> None:
    contract = new_memory_contract(
        "contextual_logic",
        provenance=["decision-log:42", "memory:a1"],
        promotion_reason="The supporting facts were reviewed together.",
        logic_kind="contradiction_resolution",
        related_ids=["a" * 32, "b" * 32],
        now=1_000.0,
    )

    restored = MemoryLayerContract.from_json_bytes(contract.to_json_bytes())

    assert restored == contract
    assert restored.logic_kind == LogicKind.CONTRADICTION_RESOLUTION
    assert restored.related_ids == ("a" * 32, "b" * 32)
    assert restored.recommendations(now=2_000.0) == {
        "promotion": "contextual_logic_is_derived_not_auto_promoted",
        "archive": "retain_with_related_memory_provenance",
    }


def test_promotion_is_explicit_ordered_and_evidenced() -> None:
    live = new_memory_contract(
        "live",
        provenance=["agent:session-1"],
        now=1_000.0,
    )
    short = live.promote(
        "short_term",
        reason="The task remains open across sessions.",
        provenance=["task:open-loop"],
        now=1_100.0,
    )
    long = short.promote(
        "long_term",
        reason="The preference was confirmed repeatedly.",
        provenance=["user:explicit"],
        now=1_200.0,
    )

    assert short.layer == MemoryLayer.SHORT_TERM
    assert short.expires_at is None
    assert len(short.promotion_history) == 1
    assert short.promotion_history[-1].source_layer == MemoryLayer.LIVE
    assert long.layer == MemoryLayer.LONG_TERM
    assert long.review_at is None
    assert long.provenance == (
        "agent:session-1",
        "task:open-loop",
        "user:explicit",
    )
    assert [event.source_layer for event in long.promotion_history] == [
        MemoryLayer.LIVE,
        MemoryLayer.SHORT_TERM,
    ]

    with pytest.raises(ValueError, match="unsupported memory promotion"):
        live.promote(
            "long_term",
            reason="Skipping review is prohibited.",
            now=1_100.0,
        )


def test_memory_contract_parser_rejects_unknown_fields() -> None:
    contract = new_memory_contract(now=1_000.0)
    decoded = json.loads(contract.to_json_bytes())
    decoded["untrusted"] = True

    with pytest.raises(ValueError, match="fields"):
        MemoryLayerContract.from_json_bytes(
            json.dumps(decoded, separators=(",", ":")).encode()
        )
