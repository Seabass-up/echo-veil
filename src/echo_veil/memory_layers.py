"""Semantic memory-layer policy shared by every agent adapter.

The four semantic layers are intentionally separate from Echo Veil's physical
L1/L2/L3 storage tiers.  A short-term record may move between active workspace
and archive without becoming long-term knowledge.  Layer changes therefore
require an explicit, protected contract rather than being inferred from where a
record happens to live.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from enum import Enum
from numbers import Real

from ._json import strict_json_loads

MEMORY_CONTRACT_VERSION = 1
MAX_MEMORY_CONTRACT_BYTES = 1024
MAX_PROVENANCE_ITEMS = 4
MAX_PROVENANCE_CHARS = 160
MAX_PROMOTION_REASON_CHARS = 240
MAX_PROMOTION_EVENTS = 2
MAX_RELATED_IDS = 8
MAX_RELATED_ID_CHARS = 128
DEFAULT_LIVE_TTL_SECONDS = 30 * 60
MAX_LIVE_TTL_SECONDS = 24 * 60 * 60
SHORT_TERM_REVIEW_SECONDS = 7 * 24 * 60 * 60
CALLER_PROVENANCE_PREFIX = "caller:"


class MemoryLayer(str, Enum):
    """The four semantic roles in the public memory contract."""

    LIVE = "live"
    SHORT_TERM = "short_term"
    LONG_TERM = "long_term"
    CONTEXTUAL_LOGIC = "contextual_logic"


class LogicKind(str, Enum):
    """Bounded relationship types for contextual-logic memories."""

    CAUSAL_CHAIN = "causal_chain"
    CONTRADICTION_RESOLUTION = "contradiction_resolution"
    DECISION = "decision"
    PRINCIPLE = "principle"


@dataclass(frozen=True, slots=True)
class PromotionEvidence:
    """Evidence for one deliberate semantic-layer transition."""

    source_layer: MemoryLayer
    promoted_at: float
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "from": self.source_layer.value,
            "at": self.promoted_at,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class MemoryLayerContract:
    """Protected semantic policy attached to one memory record."""

    layer: MemoryLayer
    provenance: tuple[str, ...]
    expires_at: float | None = None
    review_at: float | None = None
    promotion_history: tuple[PromotionEvidence, ...] = ()
    logic_kind: LogicKind | None = None
    related_ids: tuple[str, ...] = ()
    version: int = MEMORY_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.version != MEMORY_CONTRACT_VERSION:
            raise ValueError("memory contract version is unsupported")
        if not isinstance(self.layer, MemoryLayer):
            raise TypeError("memory layer must be a MemoryLayer")
        _validate_provenance(self.provenance, explicit_required=False)
        _validate_optional_timestamp(self.expires_at, "expires_at")
        _validate_optional_timestamp(self.review_at, "review_at")
        if not isinstance(self.promotion_history, tuple):
            raise TypeError("promotion_history must be a tuple")
        if len(self.promotion_history) > MAX_PROMOTION_EVENTS or any(
            not isinstance(event, PromotionEvidence) for event in self.promotion_history
        ):
            raise ValueError(
                f"promotion_history supports at most {MAX_PROMOTION_EVENTS} events"
            )
        for event in self.promotion_history:
            if not isinstance(event.source_layer, MemoryLayer):
                raise TypeError("promotion source layer must be a MemoryLayer")
            _validate_timestamp(event.promoted_at, "promotion.at")
            _validate_bounded_text(
                event.reason,
                "promotion.reason",
                MAX_PROMOTION_REASON_CHARS,
            )
        if self.logic_kind is not None and not isinstance(self.logic_kind, LogicKind):
            raise TypeError("logic_kind must be a LogicKind or None")
        _validate_related_ids(self.related_ids)

        if self.layer == MemoryLayer.LIVE:
            if self.expires_at is None:
                raise ValueError("live memory requires an expiration")
            if self.review_at is not None:
                raise ValueError("live memory does not use review_at")
        elif self.expires_at is not None:
            raise ValueError("only live memory may carry expires_at")

        if self.layer == MemoryLayer.SHORT_TERM:
            if self.review_at is None:
                raise ValueError("short-term memory requires review_at")
        elif self.review_at is not None:
            raise ValueError("only short-term memory may carry review_at")

        allowed_transitions: dict[
            MemoryLayer,
            set[tuple[tuple[MemoryLayer, MemoryLayer], ...]],
        ] = {
            MemoryLayer.LIVE: {()},
            MemoryLayer.SHORT_TERM: {
                (),
                ((MemoryLayer.LIVE, MemoryLayer.SHORT_TERM),),
            },
            # The one-event form remains readable for protected contracts
            # created by the pre-release direct-write implementation. New API
            # writes cannot create it.
            MemoryLayer.LONG_TERM: {
                ((MemoryLayer.SHORT_TERM, MemoryLayer.LONG_TERM),),
                (
                    (MemoryLayer.LIVE, MemoryLayer.SHORT_TERM),
                    (MemoryLayer.SHORT_TERM, MemoryLayer.LONG_TERM),
                ),
            },
            MemoryLayer.CONTEXTUAL_LOGIC: {
                ((MemoryLayer.SHORT_TERM, MemoryLayer.CONTEXTUAL_LOGIC),),
            },
        }
        actual_transitions = tuple(
            (
                event.source_layer,
                (
                    self.layer
                    if index == len(self.promotion_history) - 1
                    else MemoryLayer.SHORT_TERM
                ),
            )
            for index, event in enumerate(self.promotion_history)
        )
        if actual_transitions not in allowed_transitions[self.layer]:
            raise ValueError("memory promotion history is incomplete or out of order")
        if any(
            left.promoted_at > right.promoted_at
            for left, right in zip(
                self.promotion_history,
                self.promotion_history[1:],
            )
        ):
            raise ValueError("memory promotion history timestamps are out of order")

        if self.layer == MemoryLayer.CONTEXTUAL_LOGIC:
            if self.logic_kind is None or not self.related_ids:
                raise ValueError(
                    "contextual-logic memory requires a logic kind and related IDs"
                )
        elif self.logic_kind is not None or self.related_ids:
            raise ValueError(
                "logic kind and related IDs are reserved for contextual-logic memory"
            )

        encoded = self.to_json_bytes()
        if len(encoded) > MAX_MEMORY_CONTRACT_BYTES:
            raise ValueError("memory contract exceeds the protected size limit")

    def as_dict(self) -> dict[str, object]:
        return {
            "contract_version": self.version,
            "layer": self.layer.value,
            "provenance": list(self.provenance),
            "expires_at": self.expires_at,
            "review_at": self.review_at,
            "promotion_history": [event.as_dict() for event in self.promotion_history],
            "logic": (
                None
                if self.logic_kind is None
                else {
                    "kind": self.logic_kind.value,
                    "related_ids": list(self.related_ids),
                }
            ),
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(
            self.as_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> MemoryLayerContract:
        if (
            not isinstance(payload, bytes)
            or not payload
            or len(payload) > MAX_MEMORY_CONTRACT_BYTES
        ):
            raise ValueError("memory contract has an invalid size")
        try:
            decoded = strict_json_loads(payload)
        except Exception as exc:
            raise ValueError("memory contract JSON is invalid") from exc
        expected = {
            "contract_version",
            "expires_at",
            "layer",
            "logic",
            "promotion_history",
            "provenance",
            "review_at",
        }
        legacy_expected = (expected - {"promotion_history"}) | {"promotion"}
        if not isinstance(decoded, dict) or frozenset(decoded) not in {
            frozenset(expected),
            frozenset(legacy_expected),
        }:
            raise ValueError("memory contract fields are invalid")
        history_raw = decoded.get("promotion_history")
        if history_raw is None and "promotion" in decoded:
            legacy_promotion = decoded["promotion"]
            history_raw = [] if legacy_promotion is None else [legacy_promotion]
        if not isinstance(history_raw, list) or len(history_raw) > MAX_PROMOTION_EVENTS:
            raise ValueError("memory promotion history is invalid")
        promotion_history: list[PromotionEvidence] = []
        for promotion_raw in history_raw:
            if not isinstance(promotion_raw, dict) or set(promotion_raw) != {
                "at",
                "from",
                "reason",
            }:
                raise ValueError("memory promotion evidence is invalid")
            promotion_history.append(
                PromotionEvidence(
                    source_layer=_parse_layer(promotion_raw["from"]),
                    promoted_at=_validate_timestamp(
                        promotion_raw["at"],
                        "promotion.at",
                    ),
                    reason=_validate_bounded_text(
                        promotion_raw["reason"],
                        "promotion.reason",
                        MAX_PROMOTION_REASON_CHARS,
                    ),
                ),
            )
        logic_raw = decoded["logic"]
        logic_kind: LogicKind | None = None
        related_ids: tuple[str, ...] = ()
        if logic_raw is not None:
            if not isinstance(logic_raw, dict) or set(logic_raw) != {
                "kind",
                "related_ids",
            }:
                raise ValueError("memory logic metadata is invalid")
            logic_kind = _parse_logic_kind(logic_raw["kind"])
            related_ids = _validate_related_ids(logic_raw["related_ids"])
        return cls(
            layer=_parse_layer(decoded["layer"]),
            provenance=_validate_provenance(
                decoded["provenance"],
                explicit_required=False,
            ),
            expires_at=_validate_optional_timestamp(
                decoded["expires_at"],
                "expires_at",
            ),
            review_at=_validate_optional_timestamp(
                decoded["review_at"],
                "review_at",
            ),
            promotion_history=tuple(promotion_history),
            logic_kind=logic_kind,
            related_ids=related_ids,
            version=_validate_contract_version(decoded["contract_version"]),
        )

    def is_expired(self, *, now: float | None = None) -> bool:
        current = time.time() if now is None else _validate_timestamp(now, "now")
        return self.expires_at is not None and self.expires_at <= current

    def recommendations(self, *, now: float | None = None) -> dict[str, str]:
        current = time.time() if now is None else _validate_timestamp(now, "now")
        if self.layer == MemoryLayer.LIVE:
            state = "expired" if self.is_expired(now=current) else "active"
            return {
                "promotion": "promote_to_short_term_or_discard",
                "archive": f"do_not_archive_live_memory_{state}",
            }
        if self.layer == MemoryLayer.SHORT_TERM:
            due = self.review_at is not None and self.review_at <= current
            return {
                "promotion": (
                    "review_for_long_term_promotion"
                    if due
                    else "retain_short_term_until_review"
                ),
                "archive": "archive_or_discard_if_no_longer_actionable",
            }
        if self.layer == MemoryLayer.LONG_TERM:
            return {
                "promotion": "already_long_term",
                "archive": "retain_versioned_and_supersede_never_overwrite",
            }
        return {
            "promotion": "contextual_logic_is_derived_not_auto_promoted",
            "archive": "retain_with_related_memory_provenance",
        }

    def promote(
        self,
        target: MemoryLayer | str,
        *,
        reason: str,
        provenance: list[str] | tuple[str, ...] | None = None,
        now: float | None = None,
    ) -> MemoryLayerContract:
        target_layer = _parse_layer(target)
        allowed = {
            MemoryLayer.LIVE: MemoryLayer.SHORT_TERM,
            MemoryLayer.SHORT_TERM: MemoryLayer.LONG_TERM,
        }
        if allowed.get(self.layer) != target_layer:
            raise ValueError(
                f"unsupported memory promotion: {self.layer.value} -> "
                f"{target_layer.value}"
            )
        clean_reason = _validate_bounded_text(
            reason,
            "promotion reason",
            MAX_PROMOTION_REASON_CHARS,
        )
        promoted_at = time.time() if now is None else _validate_timestamp(now, "now")
        additional = (
            ()
            if provenance is None
            else _validate_provenance(provenance, explicit_required=True)
        )
        combined = tuple(dict.fromkeys((*self.provenance, *additional)))
        if len(combined) > MAX_PROVENANCE_ITEMS:
            raise ValueError(
                f"memory provenance supports at most {MAX_PROVENANCE_ITEMS} items"
            )
        if target_layer == MemoryLayer.LONG_TERM and not _has_durable_provenance(
            combined
        ):
            raise ValueError("long-term promotion requires explicit durable provenance")
        return MemoryLayerContract(
            layer=target_layer,
            provenance=combined,
            review_at=(
                promoted_at + SHORT_TERM_REVIEW_SECONDS
                if target_layer == MemoryLayer.SHORT_TERM
                else None
            ),
            promotion_history=(
                *self.promotion_history,
                PromotionEvidence(
                    source_layer=self.layer,
                    promoted_at=promoted_at,
                    reason=clean_reason,
                ),
            ),
        )

    def refresh_live(
        self,
        *,
        provenance: list[str] | tuple[str, ...] | None = None,
        expires_at: float | None = None,
        now: float | None = None,
    ) -> MemoryLayerContract:
        """Refresh bounded Live metadata without rewriting memory content."""

        if self.layer != MemoryLayer.LIVE:
            raise ValueError("only live memory can be refreshed")
        current = time.time() if now is None else _validate_timestamp(now, "now")
        additional = (
            ()
            if provenance is None
            else _validate_provenance(provenance, explicit_required=True)
        )
        combined = tuple(dict.fromkeys((*self.provenance, *additional)))
        if len(combined) > MAX_PROVENANCE_ITEMS:
            raise ValueError(
                f"memory provenance supports at most {MAX_PROVENANCE_ITEMS} items"
            )
        return MemoryLayerContract(
            layer=MemoryLayer.LIVE,
            provenance=combined,
            expires_at=_live_expiration(expires_at, now=current),
        )


def new_memory_contract(
    layer: MemoryLayer | str = MemoryLayer.SHORT_TERM,
    *,
    provenance: list[str] | tuple[str, ...] | None = None,
    promotion_reason: str | None = None,
    expires_at: float | None = None,
    logic_kind: LogicKind | str | None = None,
    related_ids: list[str] | tuple[str, ...] | None = None,
    now: float | None = None,
) -> MemoryLayerContract:
    """Validate caller intent and create a new protected layer contract."""

    current = time.time() if now is None else _validate_timestamp(now, "now")
    clean_layer = _parse_layer(layer)
    if clean_layer == MemoryLayer.LONG_TERM:
        raise ValueError("long-term memory must be promoted from short-term memory")
    explicit_provenance = provenance is not None
    clean_provenance = _validate_provenance(
        ("caller:unspecified",) if provenance is None else provenance,
        explicit_required=clean_layer == MemoryLayer.CONTEXTUAL_LOGIC,
    )
    promotion_history: tuple[PromotionEvidence, ...]
    if clean_layer == MemoryLayer.CONTEXTUAL_LOGIC:
        if not explicit_provenance or not _has_durable_provenance(clean_provenance):
            raise ValueError(
                f"{clean_layer.value} memory requires explicit provenance with "
                "non-caller evidence"
            )
        clean_reason = _validate_bounded_text(
            promotion_reason,
            "promotion reason",
            MAX_PROMOTION_REASON_CHARS,
        )
        promotion_history = (
            PromotionEvidence(
                source_layer=MemoryLayer.SHORT_TERM,
                promoted_at=current,
                reason=clean_reason,
            ),
        )
    elif promotion_reason is not None:
        raise ValueError("promotion_reason is only valid for contextual-logic writes")
    else:
        promotion_history = ()

    if clean_layer == MemoryLayer.LIVE:
        expiration = _live_expiration(expires_at, now=current)
    elif expires_at is not None:
        raise ValueError("expires_at is only valid for live memory")
    else:
        expiration = None

    if clean_layer == MemoryLayer.SHORT_TERM:
        review_at = current + SHORT_TERM_REVIEW_SECONDS
    else:
        review_at = None

    if clean_layer == MemoryLayer.CONTEXTUAL_LOGIC:
        clean_logic_kind = _parse_logic_kind(logic_kind)
        clean_related_ids = _validate_related_ids(related_ids)
        if not clean_related_ids:
            raise ValueError("contextual-logic memory requires related IDs")
    elif logic_kind is not None or related_ids is not None:
        raise ValueError(
            "logic_kind and related_ids are only valid for contextual-logic memory"
        )
    else:
        clean_logic_kind = None
        clean_related_ids = ()

    return MemoryLayerContract(
        layer=clean_layer,
        provenance=clean_provenance,
        expires_at=expiration,
        review_at=review_at,
        promotion_history=promotion_history,
        logic_kind=clean_logic_kind,
        related_ids=clean_related_ids,
    )


def migrated_short_term_contract(*, created_at: float) -> MemoryLayerContract:
    """Create an honest protected contract for a pre-contract secure record."""

    timestamp = _validate_timestamp(created_at, "created_at")
    return MemoryLayerContract(
        layer=MemoryLayer.SHORT_TERM,
        provenance=("migration:pre-layer-contract",),
        review_at=timestamp + SHORT_TERM_REVIEW_SECONDS,
    )


def _parse_layer(value: object) -> MemoryLayer:
    if isinstance(value, MemoryLayer):
        return value
    if not isinstance(value, str):
        raise TypeError("memory layer must be a string or MemoryLayer")
    try:
        return MemoryLayer(value.strip().lower())
    except ValueError as exc:
        raise ValueError(
            "memory layer must be live, short_term, long_term, or contextual_logic"
        ) from exc


def _parse_logic_kind(value: object) -> LogicKind:
    if isinstance(value, LogicKind):
        return value
    if not isinstance(value, str):
        raise TypeError("logic kind must be a string or LogicKind")
    try:
        return LogicKind(value.strip().lower())
    except ValueError as exc:
        raise ValueError(
            "logic kind must be causal_chain, contradiction_resolution, "
            "decision, or principle"
        ) from exc


def _validate_contract_version(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("memory contract version must be an integer")
    if value != MEMORY_CONTRACT_VERSION:
        raise ValueError("memory contract version is unsupported")
    return value


def _validate_bounded_text(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    clean = " ".join(value.strip().split())
    if (
        not clean
        or len(clean) > limit
        or not clean.isprintable()
        or any(ord(character) < 0x20 for character in clean)
    ):
        raise ValueError(f"{label} must be a bounded printable string")
    return clean


def _validate_provenance(
    value: object,
    *,
    explicit_required: bool,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise TypeError("memory provenance must be a list or tuple")
    if not value and explicit_required:
        raise ValueError("memory provenance must not be empty")
    if not 1 <= len(value) <= MAX_PROVENANCE_ITEMS:
        raise ValueError(
            f"memory provenance must contain 1 to {MAX_PROVENANCE_ITEMS} items"
        )
    cleaned = tuple(
        _validate_bounded_text(item, "provenance item", MAX_PROVENANCE_CHARS)
        for item in value
    )
    if len(set(cleaned)) != len(cleaned):
        raise ValueError("memory provenance items must be unique")
    return cleaned


def _has_durable_provenance(value: tuple[str, ...]) -> bool:
    """Return whether provenance contains evidence beyond transport identity."""

    return any(
        not item.casefold().startswith(CALLER_PROVENANCE_PREFIX) for item in value
    )


def _validate_related_ids(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise TypeError("related_ids must be a list or tuple")
    if len(value) > MAX_RELATED_IDS:
        raise ValueError(f"related_ids supports at most {MAX_RELATED_IDS} items")
    cleaned = tuple(
        _validate_bounded_text(item, "related memory ID", MAX_RELATED_ID_CHARS)
        for item in value
    )
    if len(set(cleaned)) != len(cleaned):
        raise ValueError("related memory IDs must be unique")
    return cleaned


def _validate_timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{label} must be a finite non-negative timestamp")
    timestamp = float(value)
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError(f"{label} must be a finite non-negative timestamp")
    return timestamp


def _live_expiration(value: object, *, now: float) -> float:
    expiration = (
        now + DEFAULT_LIVE_TTL_SECONDS
        if value is None
        else _validate_timestamp(value, "expires_at")
    )
    if not now < expiration <= now + MAX_LIVE_TTL_SECONDS:
        raise ValueError(
            "live memory expiration must be in the future and within 24 hours"
        )
    return expiration


def _validate_optional_timestamp(value: object, label: str) -> float | None:
    return None if value is None else _validate_timestamp(value, label)


__all__ = [
    "DEFAULT_LIVE_TTL_SECONDS",
    "LogicKind",
    "MemoryLayer",
    "MemoryLayerContract",
    "PromotionEvidence",
    "migrated_short_term_contract",
    "new_memory_contract",
]
