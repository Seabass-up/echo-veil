"""JSON-RPC and MCP entry points for supported agent integrations."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, BinaryIO, cast

from . import __version__
from ._json import strict_json_loads
from .agent_broker import BrokerClient, BrokerServer, default_broker_socket
from .agent_memory import (
    AgentMemory,
    AlwaysAvailableMemory,
    DEFAULT_CAPACITY,
    DEFAULT_EMBEDDING_TIMEOUT_SECONDS,
    DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    DEFAULT_PROFILE_LOCK_TIMEOUT_SECONDS,
    EmbeddingUnavailable,
    HashingTextEmbedder,
    MAX_AGENT_MEMORY_WRITE_CHARS,
    OllamaTextEmbedder,
    TextEmbedder,
)
from .memory_layers import LogicKind, MemoryLayer

MCP_PROTOCOL_VERSION = "2025-11-25"
MAX_REQUEST_BYTES = 1_048_576
MIN_HOST_RECALL_RESULTS = 2
MAX_CALLER_SUPPLIED_PROVENANCE_ITEMS = 3
SERVER_INSTRUCTIONS = (
    "Echo Veil is opt-in agent memory with four shielded semantic layers. Use "
    "Live only for bounded present-state memory, Short-Term for provisional "
    "continuity, Long-Term only through explicit promotion with provenance, "
    "and Contextual Logic only for a typed relationship among existing memories. "
    "Write compact intent/outcome seed crystals rather than transcripts; use "
    "echo_veil_refresh_live to update active state without silent overwrite. "
    "A host-delivered exact-turn runtime_status with ritual_satisfied=true "
    "satisfies its completed doctor, recall, and applicable context checks only "
    "for that turn; do not repeat them. Otherwise call echo_veil_recall before "
    "relying on stored facts and use "
    "echo_veil_context only when the protected Contextual Logic path is needed. "
    "State returned layers and provenance, respect gated results, follow "
    "promotion/archive recommendations, and use echo_veil_forget for explicit "
    "erasure. Never invent a memory when results are empty. Context evidence is "
    "an authenticated relationship, not an independently query-scored answer. "
    "When ranking_ambiguous=true, preserve both leading candidates. When "
    "competing_memory_detected=true, preserve every returned group member and "
    "never invent a resolution; use explicit supersession or protected Contextual "
    "Logic. A degraded response is keyed read-only recall, not semantic or "
    "authoritative retrieval. Do not treat the local AES shield as a production "
    "enclave."
)

BaseMemoryAdapter = AgentMemory | AlwaysAvailableMemory


class _RuntimeAvailabilityMemory:
    """Transition a live CLI adapter to read-only recall on a real outage."""

    def __init__(
        self,
        memory: BaseMemoryAdapter,
        state_dir: Path | None,
        profile: str,
        scope: str = "local-user",
    ) -> None:
        self._memory = memory
        self._state_dir = state_dir
        self._profile = profile
        self._scope = scope
        self._closed = False

    def _degrade(self) -> AlwaysAvailableMemory:
        if isinstance(self._memory, AlwaysAvailableMemory):
            return self._memory
        self._memory.close()
        self._memory = AlwaysAvailableMemory(
            self._state_dir,
            profile=self._profile,
            scope=self._scope,
            reason="runtime_embedding_service_unavailable",
        )
        return self._memory

    @property
    def profile_dir(self) -> Path:
        return self._memory.profile_dir

    @property
    def scope(self) -> str:
        return self._memory.scope

    def remember(
        self,
        topic: str,
        payload: str,
        *,
        effective_at: float | None = None,
        supersedes: list[str] | tuple[str, ...] | None = None,
        layer: MemoryLayer | str = MemoryLayer.SHORT_TERM,
        provenance: list[str] | tuple[str, ...] | None = None,
        promotion_reason: str | None = None,
        expires_at: float | None = None,
        logic_kind: LogicKind | str | None = None,
        related_ids: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        try:
            return self._memory.remember(
                topic,
                payload,
                effective_at=effective_at,
                supersedes=supersedes,
                layer=layer,
                provenance=provenance,
                promotion_reason=promotion_reason,
                expires_at=expires_at,
                logic_kind=logic_kind,
                related_ids=related_ids,
            )
        except EmbeddingUnavailable:
            return self._degrade().remember(
                topic,
                payload,
                effective_at=effective_at,
                supersedes=supersedes,
                layer=layer,
                provenance=provenance,
                promotion_reason=promotion_reason,
                expires_at=expires_at,
                logic_kind=logic_kind,
                related_ids=related_ids,
            )

    def promote(
        self,
        vine_id: str,
        target_layer: MemoryLayer | str,
        *,
        reason: str,
        provenance: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        return self._memory.promote(
            vine_id,
            target_layer,
            reason=reason,
            provenance=provenance,
        )

    def refresh_live(
        self,
        vine_id: str,
        payload: str,
        *,
        provenance: list[str] | tuple[str, ...] | None = None,
        expires_at: float | None = None,
    ) -> dict[str, Any]:
        try:
            return self._memory.refresh_live(
                vine_id,
                payload,
                provenance=provenance,
                expires_at=expires_at,
            )
        except EmbeddingUnavailable:
            return self._degrade().refresh_live(
                vine_id,
                payload,
                provenance=provenance,
                expires_at=expires_at,
            )

    def recall(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float | None = None,
        allow_inferential: bool = False,
        as_of: float | None = None,
        layers: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        try:
            return self._memory.recall(
                query,
                top_k=top_k,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
                layers=layers,
            )
        except EmbeddingUnavailable:
            return self._degrade().recall(
                query,
                top_k=top_k,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
                layers=layers,
            )

    def preview_recall(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float | None = None,
        allow_inferential: bool = False,
        as_of: float | None = None,
        layers: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        try:
            preview = getattr(self._memory, "preview_recall", None)
            if callable(preview):
                return preview(
                    query,
                    top_k=top_k,
                    min_score=min_score,
                    allow_inferential=allow_inferential,
                    as_of=as_of,
                    layers=layers,
                )
            return self._memory.recall(
                query,
                top_k=top_k,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
                layers=layers,
            )
        except EmbeddingUnavailable:
            return self._degrade().recall(
                query,
                top_k=top_k,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
                layers=layers,
            )

    def availability_recall(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float | None = None,
        as_of: float | None = None,
        layers: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        """Force one encrypted, lifecycle-neutral availability lookup.

        RPC processes are short lived. Closing the semantic adapter before
        opening the read-only payload store prevents this diagnostic path from
        sharing a writer or silently falling back to ordinary semantic recall.
        """

        return self._degrade().recall(
            query,
            top_k=top_k,
            min_score=min_score,
            allow_inferential=False,
            as_of=as_of,
            layers=layers,
        )

    def context(
        self,
        query: str,
        *,
        min_score: float | None = None,
        allow_inferential: bool = False,
        as_of: float | None = None,
        max_depth: int = 1,
        max_records: int = 8,
    ) -> dict[str, Any]:
        try:
            return self._memory.context(
                query,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
                max_depth=max_depth,
                max_records=max_records,
            )
        except EmbeddingUnavailable:
            return self._degrade().context(
                query,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
                max_depth=max_depth,
                max_records=max_records,
            )

    def preview_context(
        self,
        query: str,
        *,
        min_score: float | None = None,
        allow_inferential: bool = False,
        as_of: float | None = None,
        max_depth: int = 1,
        max_records: int = 8,
    ) -> dict[str, Any]:
        try:
            preview = getattr(self._memory, "preview_context", None)
            if callable(preview):
                return preview(
                    query,
                    min_score=min_score,
                    allow_inferential=allow_inferential,
                    as_of=as_of,
                    max_depth=max_depth,
                    max_records=max_records,
                )
            return self._memory.context(
                query,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
                max_depth=max_depth,
                max_records=max_records,
            )
        except EmbeddingUnavailable:
            return self._degrade().context(
                query,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
                max_depth=max_depth,
                max_records=max_records,
            )

    def forget(self, vine_id: str) -> dict[str, Any]:
        return self._memory.forget(vine_id)

    def list_memories(
        self,
        *,
        limit: int = 1000,
        layers: list[str] | tuple[str, ...] | None = None,
        topic_prefix: str | None = None,
        newest_first: bool = False,
    ) -> list[dict[str, Any]]:
        return self._memory.list_memories(
            limit=limit,
            layers=layers,
            topic_prefix=topic_prefix,
            newest_first=newest_first,
        )

    def reindex(self) -> dict[str, Any]:
        try:
            return self._memory.reindex()
        except EmbeddingUnavailable:
            return self._degrade().reindex()

    def doctor(self) -> dict[str, Any]:
        report = dict(self._memory.doctor())
        report["runtime_failover_enabled"] = True
        report["runtime_failover_active"] = isinstance(
            self._memory,
            AlwaysAvailableMemory,
        )
        return report

    def rotate_key(
        self,
        *,
        confirm: bool = False,
        batch_size: int = 100,
    ) -> dict[str, Any]:
        rotate = getattr(self._memory, "rotate_key", None)
        if not callable(rotate):
            raise RuntimeError("key rotation is unavailable in read-only mode")
        return rotate(confirm=confirm, batch_size=batch_size)

    def retire_previous_key(
        self,
        *,
        confirm_backups_accounted_for: bool = False,
    ) -> dict[str, Any]:
        retire = getattr(self._memory, "retire_previous_key", None)
        if not callable(retire):
            raise RuntimeError("key retirement is unavailable in read-only mode")
        return retire(confirm_backups_accounted_for=confirm_backups_accounted_for)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._memory.close()

    def __enter__(self) -> _RuntimeAvailabilityMemory:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


MemoryAdapter = AgentMemory | AlwaysAvailableMemory | _RuntimeAvailabilityMemory
MemoryFactory = Callable[[], MemoryAdapter]
RpcDispatcher = Callable[[str, Mapping[str, Any]], dict[str, Any]]

_ABSOLUTE_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/](?:[^\s\\/]+[\\/])+[^\s]+|/(?:[^\s/]+/)+[^\s]+)"
)
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_ -]?key|authorization|credential|password|private[_ -]?key|"
    r"secret|token)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+"
)
_BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+[A-Z0-9._~+/=-]+")
_CALLER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MAX_PUBLIC_ERROR_CHARS = 512


TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "echo_veil_remember",
        "description": (
            "Store one user-authorized compact intent/outcome memory in the "
            "local encrypted Echo Veil profile. Raw transcripts are rejected "
            "outside bounded Live state. Exact retries are deduplicated."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["topic", "payload"],
            "properties": {
                "topic": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 512,
                    "description": "Short label; scoped-v2 profiles encrypt it at rest.",
                },
                "payload": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_AGENT_MEMORY_WRITE_CHARS,
                    "description": (
                        "Compact authorized memory content. Per-layer limits "
                        "are enforced by Echo Veil."
                    ),
                },
                "effective_at": {
                    "type": "number",
                    "minimum": 0,
                    "description": "Optional Unix timestamp when this fact became valid.",
                },
                "supersedes": {
                    "type": "array",
                    "maxItems": 20,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 128},
                    "description": (
                        "Prior vine IDs this fact explicitly replaces. History is preserved."
                    ),
                },
                "layer": {
                    "type": "string",
                    "enum": [
                        "live",
                        "short_term",
                        "contextual_logic",
                    ],
                    "description": (
                        "Creation layer. Defaults to short_term. Long-term is "
                        "created only through echo_veil_promote. Contextual Logic "
                        "requires explicit provenance and promotion_reason."
                    ),
                },
                "provenance": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_CALLER_SUPPLIED_PROVENANCE_ITEMS,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 160},
                    "description": (
                        "Bounded source or evidence references. The configured "
                        "host caller is added separately by bundled adapters."
                    ),
                },
                "promotion_reason": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 240,
                    "description": (
                        "Required justification for contextual-logic derivation."
                    ),
                },
                "expires_at": {
                    "type": "number",
                    "minimum": 0,
                    "description": (
                        "Live-memory expiration. Defaults to 30 minutes and may "
                        "not exceed 24 hours."
                    ),
                },
                "logic_kind": {
                    "type": "string",
                    "enum": [
                        "causal_chain",
                        "contradiction_resolution",
                        "decision",
                        "principle",
                    ],
                    "description": "Required for contextual-logic memory.",
                },
                "related_ids": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 128},
                    "description": (
                        "Existing memory IDs supporting a contextual-logic record."
                    ),
                },
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_refresh_live",
        "description": (
            "Refresh one current Live memory. Changed content creates a new "
            "shielded version that explicitly supersedes the prior record; "
            "unchanged content only renews protected Live metadata."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["vine_id", "payload"],
            "properties": {
                "vine_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                },
                "payload": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_AGENT_MEMORY_WRITE_CHARS,
                    "description": "Bounded current working-state content.",
                },
                "provenance": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_CALLER_SUPPLIED_PROVENANCE_ITEMS,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 160},
                },
                "expires_at": {
                    "type": "number",
                    "minimum": 0,
                    "description": (
                        "Renewed Live expiration. Defaults to 30 minutes and "
                        "may not exceed 24 hours."
                    ),
                },
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_promote",
        "description": (
            "Deliberately promote a shielded memory from Live to Short-Term or "
            "from Short-Term to Long-Term with a bounded reason. Long-Term also "
            "requires explicit durable provenance and compact seed content."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["vine_id", "target_layer", "reason"],
            "properties": {
                "vine_id": {"type": "string", "minLength": 1, "maxLength": 128},
                "target_layer": {
                    "type": "string",
                    "enum": ["short_term", "long_term"],
                },
                "reason": {"type": "string", "minLength": 1, "maxLength": 240},
                "provenance": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_CALLER_SUPPLIED_PROVENANCE_ITEMS,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 160},
                },
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_recall",
        "description": (
            "Recall relevant local Echo Veil memories without advancing decay "
            "or reinforcement. Ordinary recall is lifecycle-neutral. During an "
            "embedding outage, an explicitly marked read-only availability layer "
            "can return only strong keyed lexical matches. Payloads are withheld "
            "when confidence policy gates them. Preserve both leading results "
            "when ranking_ambiguous=true and every returned possible-conflict "
            "group member when competing_memory_detected=true. Never infer a "
            "conflict resolution; degraded results are neither semantic nor "
            "authoritative."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 20000},
                "top_k": {
                    "type": "integer",
                    "minimum": MIN_HOST_RECALL_RESULTS,
                    "maximum": 20,
                    "description": (
                        "At least two candidates are retained so ranking ambiguity "
                        "cannot be hidden by the caller."
                    ),
                },
                "min_score": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "description": (
                        "Optional override. When omitted, the selected embedding "
                        "backend's calibrated threshold is used."
                    ),
                },
                "allow_inferential": {
                    "type": "boolean",
                    "description": (
                        "Use only after the user explicitly authorizes inferential recall."
                    ),
                },
                "as_of": {
                    "type": "number",
                    "minimum": 0,
                    "description": (
                        "Optional Unix timestamp for point-in-time fact retrieval."
                    ),
                },
                "layers": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4,
                    "uniqueItems": True,
                    "items": {
                        "type": "string",
                        "enum": [
                            "live",
                            "short_term",
                            "long_term",
                            "contextual_logic",
                        ],
                    },
                    "description": (
                        "Optional semantic-layer scope. Filtering does not boost "
                        "or rewrite confidence scores."
                    ),
                },
            },
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_context",
        "description": (
            "Find up to two confidence-checked Contextual Logic roots, then return "
            "a bounded trace of only their authenticated outgoing evidence links. "
            "Linked evidence is explicitly not independently query-scored, and no "
            "answer or explanation is synthesized."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 20000},
                "min_score": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                },
                "allow_inferential": {
                    "type": "boolean",
                    "description": (
                        "Use only after the user explicitly authorizes inferential recall."
                    ),
                },
                "as_of": {"type": "number", "minimum": 0},
                "max_depth": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 2,
                    "description": "Maximum authenticated outgoing-link depth.",
                },
                "max_records": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                    "description": "Maximum linked evidence records returned.",
                },
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_forget",
        "description": (
            "Delete one memory payload and its Echo Veil lifecycle/index state "
            "from the local profile."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["vine_id"],
            "properties": {
                "vine_id": {"type": "string", "minLength": 1, "maxLength": 128}
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_list",
        "description": (
            "Return a bounded, authenticated inventory for administrative recent-"
            "memory views. This is not semantic recall, does not reinforce or decay "
            "records, and must not be injected wholesale into model context."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "layers": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4,
                    "uniqueItems": True,
                    "items": {
                        "type": "string",
                        "enum": [
                            "live",
                            "short_term",
                            "long_term",
                            "contextual_logic",
                        ],
                    },
                },
                "topic_prefix": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 512,
                },
                "newest_first": {"type": "boolean"},
            },
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_doctor",
        "description": (
            "Report local adapter health, counts, file protection, core "
            "capabilities, and explicit production limitations."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_reindex",
        "description": (
            "Rebuild protected multi-vector and keyed lexical retrieval data for "
            "the current profile. Requires explicit confirmation."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["confirm"],
            "properties": {"confirm": {"const": True}},
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_rotate_key",
        "description": (
            "Start or resume a bounded local profile key rotation. New writes use "
            "the new key immediately; old keys remain available until verification."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["confirm"],
            "properties": {
                "confirm": {"const": True},
                "batch_size": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                },
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "echo_veil_retire_key",
        "description": (
            "Retire the verified previous local key only after old-key backups "
            "have been accounted for. This does not promise physical media erasure."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["confirm_backups_accounted_for"],
            "properties": {"confirm_backups_accounted_for": {"const": True}},
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
)

OPERATOR_TOOL_NAMES = frozenset(
    {
        "echo_veil_rotate_key",
        "echo_veil_retire_key",
    }
)
AGENT_TOOLS: tuple[dict[str, Any], ...] = tuple(
    tool for tool in TOOLS if tool["name"] not in OPERATOR_TOOL_NAMES
)


def dispatch(
    memory: MemoryAdapter,
    action: str,
    arguments: Mapping[str, Any],
    *,
    caller: str | None = None,
) -> dict[str, Any]:
    if not isinstance(action, str):
        raise TypeError("action must be a string")
    if not isinstance(arguments, Mapping):
        raise TypeError("arguments must be an object")
    supplied = dict(arguments)
    if action in {"remember", "echo_veil_remember"}:
        _require_only(
            supplied,
            {
                "topic",
                "payload",
                "effective_at",
                "supersedes",
                "layer",
                "provenance",
                "promotion_reason",
                "expires_at",
                "logic_kind",
                "related_ids",
            },
        )
        return memory.remember(
            topic=_required_string(supplied, "topic"),
            payload=_required_string(supplied, "payload"),
            effective_at=supplied.get("effective_at"),  # type: ignore[arg-type]
            supersedes=supplied.get("supersedes"),  # type: ignore[arg-type]
            layer=supplied.get("layer", MemoryLayer.SHORT_TERM),  # type: ignore[arg-type]
            provenance=_with_caller_provenance(
                supplied.get("provenance"),
                caller,
            ),
            promotion_reason=supplied.get("promotion_reason"),  # type: ignore[arg-type]
            expires_at=supplied.get("expires_at"),  # type: ignore[arg-type]
            logic_kind=supplied.get("logic_kind"),  # type: ignore[arg-type]
            related_ids=supplied.get("related_ids"),  # type: ignore[arg-type]
        )
    if action in {"refresh_live", "echo_veil_refresh_live"}:
        _require_only(
            supplied,
            {"vine_id", "payload", "provenance", "expires_at"},
        )
        return memory.refresh_live(
            _required_string(supplied, "vine_id"),
            _required_string(supplied, "payload"),
            provenance=_with_caller_provenance(
                supplied.get("provenance"),
                caller,
            ),
            expires_at=supplied.get("expires_at"),  # type: ignore[arg-type]
        )
    if action in {"promote", "echo_veil_promote"}:
        _require_only(
            supplied,
            {"vine_id", "target_layer", "reason", "provenance"},
        )
        return memory.promote(
            _required_string(supplied, "vine_id"),
            _required_string(supplied, "target_layer"),
            reason=_required_string(supplied, "reason"),
            provenance=_with_caller_provenance(
                supplied.get("provenance"),
                caller,
            ),
        )
    if action in {"recall", "echo_veil_recall"}:
        _require_only(
            supplied,
            {
                "query",
                "top_k",
                "min_score",
                "allow_inferential",
                "as_of",
                "layers",
            },
        )
        requested_top_k = supplied.get("top_k", 5)
        if isinstance(requested_top_k, bool) or not isinstance(requested_top_k, int):
            raise TypeError("top_k must be an integer")
        if not 1 <= requested_top_k <= 20:
            raise ValueError("top_k must be between 1 and 20")
        effective_top_k = max(MIN_HOST_RECALL_RESULTS, requested_top_k)
        response = memory.recall(
            query=_required_string(supplied, "query"),
            top_k=effective_top_k,
            min_score=supplied.get("min_score"),  # type: ignore[arg-type]
            allow_inferential=supplied.get("allow_inferential", False),  # type: ignore[arg-type]
            as_of=supplied.get("as_of"),  # type: ignore[arg-type]
            layers=supplied.get("layers"),  # type: ignore[arg-type]
        )
        response["requested_top_k"] = requested_top_k
        response["effective_top_k"] = effective_top_k
        response["ambiguity_candidates_preserved"] = effective_top_k >= 2
        response["competing_candidates_preserved"] = bool(
            response.get("competing_pair_preserved", False)
        )
        return response
    if action == "availability_recall":
        _require_only(
            supplied,
            {"query", "top_k", "min_score", "as_of", "layers"},
        )
        requested_top_k = supplied.get("top_k", 5)
        if isinstance(requested_top_k, bool) or not isinstance(requested_top_k, int):
            raise TypeError("top_k must be an integer")
        if not 1 <= requested_top_k <= 20:
            raise ValueError("top_k must be between 1 and 20")
        effective_top_k = max(MIN_HOST_RECALL_RESULTS, requested_top_k)
        arguments_value = {
            "query": _required_string(supplied, "query"),
            "top_k": effective_top_k,
            "min_score": supplied.get("min_score"),
            "as_of": supplied.get("as_of"),
            "layers": supplied.get("layers"),
        }
        if isinstance(memory, _RuntimeAvailabilityMemory):
            response = memory.availability_recall(**arguments_value)  # type: ignore[arg-type]
        elif isinstance(memory, AlwaysAvailableMemory):
            response = memory.recall(
                **arguments_value,  # type: ignore[arg-type]
                allow_inferential=False,
            )
        else:
            raise RuntimeError(
                "availability recall requires the explicit read-only availability layer"
            )
        if (
            response.get("degraded") is not True
            or response.get("semantic_available") is not False
            or response.get("lifecycle_mutated") is not False
        ):
            raise RuntimeError("availability recall did not remain read-only")
        response["requested_top_k"] = requested_top_k
        response["effective_top_k"] = effective_top_k
        response["ambiguity_candidates_preserved"] = effective_top_k >= 2
        response["competing_candidates_preserved"] = bool(
            response.get("competing_pair_preserved", False)
        )
        response["model_turn_authorized"] = False
        response["mutations_allowed"] = False
        return response
    if action in {"context", "echo_veil_context"}:
        _require_only(
            supplied,
            {
                "query",
                "min_score",
                "allow_inferential",
                "as_of",
                "max_depth",
                "max_records",
            },
        )
        return memory.context(
            query=_required_string(supplied, "query"),
            min_score=supplied.get("min_score"),  # type: ignore[arg-type]
            allow_inferential=supplied.get("allow_inferential", False),  # type: ignore[arg-type]
            as_of=supplied.get("as_of"),  # type: ignore[arg-type]
            max_depth=supplied.get("max_depth", 1),  # type: ignore[arg-type]
            max_records=supplied.get("max_records", 8),  # type: ignore[arg-type]
        )
    if action == "preflight_v2":
        _require_only(
            supplied,
            {
                "query",
                "expected_profile",
                "expected_scope",
                "query_source",
                "session_id",
                "turn_id",
                "model_digest",
                "tool_manifest_digest",
                "artifact_authority_id",
            },
        )
        if caller is None:
            raise RuntimeError("preflight requires a bounded caller identity")
        # This action is RPC-only and is not advertised as a model-callable tool.
        from .agent_preflight import (
            PREFLIGHT_HOSTS,
            PreflightV2Memory,
            prepare_preflight_v2,
        )
        from .preflight_receipt import PreflightReceiptAuthority

        if caller not in PREFLIGHT_HOSTS:
            raise RuntimeError("preflight caller is unsupported")
        expected_profile = _required_string(supplied, "expected_profile")
        expected_scope = _required_string(supplied, "expected_scope")
        if (
            _CALLER_ID.fullmatch(expected_profile) is None
            or memory.profile_dir.name != expected_profile
        ):
            raise ValueError("expected_profile does not match the open profile")
        if (
            _CALLER_ID.fullmatch(expected_scope) is None
            or memory.scope != expected_scope
        ):
            raise ValueError("expected_scope does not match the open profile")
        if not callable(getattr(memory, "preview_recall", None)) or not callable(
            getattr(memory, "preview_context", None)
        ):
            raise RuntimeError("lifecycle-neutral semantic preflight is unavailable")
        query_source = supplied.get("query_source", "current_user_prompt")
        if not isinstance(query_source, str):
            raise TypeError("query_source must be a string")
        authority = PreflightReceiptAuthority(memory.profile_dir)
        return prepare_preflight_v2(
            cast(PreflightV2Memory, memory),
            _required_string(supplied, "query"),
            authority=authority,
            host=caller,
            profile=expected_profile,
            scope=expected_scope,
            session_id=_required_string(supplied, "session_id"),
            turn_id=_required_string(supplied, "turn_id"),
            model_digest=_required_string(supplied, "model_digest"),
            tool_manifest_digest=_required_string(
                supplied,
                "tool_manifest_digest",
            ),
            artifact_authority_id=_required_string(
                supplied,
                "artifact_authority_id",
            ),
            query_source=query_source,
        )
    if action == "preflight":
        _require_only(
            supplied,
            {
                "query",
                "expected_profile",
                "expected_scope",
                "expected_model",
                "expected_dimension",
                "query_source",
            },
        )
        if caller is None:
            raise RuntimeError("preflight requires a bounded caller identity")
        # Import lazily because the hook entry point opens this CLI adapter.
        # The action is intentionally RPC-only and is never advertised as a
        # model-callable MCP tool.
        from .agent_preflight import PREFLIGHT_HOSTS, prepare_preflight

        if caller not in PREFLIGHT_HOSTS:
            raise RuntimeError("preflight caller is unsupported")
        expected_profile = supplied.get(
            "expected_profile",
            "echo-universal-qwen3-v1",
        )
        if (
            not isinstance(expected_profile, str)
            or _CALLER_ID.fullmatch(expected_profile) is None
        ):
            raise ValueError("expected_profile must be a bounded profile identifier")
        memory_scope = getattr(memory, "scope", "local-user")
        expected_scope = supplied.get("expected_scope", memory_scope)
        if (
            not isinstance(expected_scope, str)
            or _CALLER_ID.fullmatch(expected_scope) is None
            or memory_scope != expected_scope
        ):
            raise ValueError("expected_scope does not match the open profile")
        expected_model = supplied.get("expected_model", DEFAULT_OLLAMA_MODEL)
        if (
            not isinstance(expected_model, str)
            or not expected_model
            or len(expected_model) > 256
        ):
            raise ValueError("expected_model must be a bounded model identifier")
        expected_dimension = supplied.get(
            "expected_dimension",
            DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
        )
        if (
            isinstance(expected_dimension, bool)
            or not isinstance(expected_dimension, int)
            or expected_dimension < 1
        ):
            raise ValueError("expected_dimension must be a positive integer")
        query_source = supplied.get("query_source", "current_user_prompt")
        if not isinstance(query_source, str):
            raise TypeError("query_source must be a string")
        context = prepare_preflight(
            memory,
            _required_string(supplied, "query"),
            host=caller,
            expected_profile=expected_profile,
            expected_model=expected_model,
            expected_dimension=expected_dimension,
            query_source=query_source,
        )
        return {
            "preflight_ready": True,
            "memory_authority": "echo-veil",
            "host": caller,
            "profile": expected_profile,
            "scope": expected_scope,
            "query_source": query_source,
            "semantic": True,
            "context": context,
        }
    if action in {"forget", "echo_veil_forget"}:
        _require_only(supplied, {"vine_id"})
        return memory.forget(_required_string(supplied, "vine_id"))
    if action in {"list", "echo_veil_list"}:
        _require_only(
            supplied,
            {"limit", "layers", "topic_prefix", "newest_first"},
        )
        requested_limit = supplied.get("limit", 20)
        if isinstance(requested_limit, bool) or not isinstance(requested_limit, int):
            raise TypeError("limit must be an integer")
        if not 1 <= requested_limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        newest_first = supplied.get("newest_first", True)
        if not isinstance(newest_first, bool):
            raise TypeError("newest_first must be a boolean")
        topic_prefix = supplied.get("topic_prefix")
        if topic_prefix is not None and not isinstance(topic_prefix, str):
            raise TypeError("topic_prefix must be a string")
        records = memory.list_memories(
            limit=requested_limit + 1,
            layers=supplied.get("layers"),  # type: ignore[arg-type]
            topic_prefix=topic_prefix,
            newest_first=newest_first,
        )
        truncated = len(records) > requested_limit
        if truncated:
            del records[requested_limit:]
        return {
            "results": records,
            "count": len(records),
            "truncated": truncated,
            "inventory_only": True,
            "semantic_retrieval_performed": False,
            "lifecycle_mutated": False,
            "newest_first": newest_first,
            "topic_prefix_applied": topic_prefix is not None,
            "layers_involved": sorted(
                {
                    str(record["memory_layer"])
                    for record in records
                    if isinstance(record.get("memory_layer"), str)
                }
            ),
            "requested_layers": supplied.get(
                "layers",
                [layer.value for layer in MemoryLayer],
            ),
        }
    if action in {"doctor", "echo_veil_doctor"}:
        _require_only(supplied, set())
        return memory.doctor()
    if action in {"reindex", "echo_veil_reindex"}:
        _require_only(supplied, {"confirm"})
        if supplied.get("confirm") is not True:
            raise ValueError("reindex requires confirm=true")
        return memory.reindex()
    if action in {"rotate_key", "echo_veil_rotate_key"}:
        _require_only(supplied, {"confirm", "batch_size"})
        if supplied.get("confirm") is not True:
            raise ValueError("key rotation requires confirm=true")
        batch_size = supplied.get("batch_size", 100)
        if isinstance(batch_size, bool) or not isinstance(batch_size, int):
            raise TypeError("batch_size must be an integer")
        rotate = getattr(memory, "rotate_key", None)
        if not callable(rotate):
            raise RuntimeError("key rotation is unavailable")
        return rotate(confirm=True, batch_size=batch_size)
    if action in {"retire_key", "echo_veil_retire_key"}:
        _require_only(supplied, {"confirm_backups_accounted_for"})
        if supplied.get("confirm_backups_accounted_for") is not True:
            raise ValueError(
                "key retirement requires confirm_backups_accounted_for=true"
            )
        retire = getattr(memory, "retire_previous_key", None)
        if not callable(retire):
            raise RuntimeError("key retirement is unavailable")
        return retire(confirm_backups_accounted_for=True)
    raise ValueError(f"unknown Echo Veil action: {action}")


class McpServer:
    def __init__(
        self,
        memory: MemoryAdapter | None = None,
        *,
        memory_factory: MemoryFactory | None = None,
        rpc_dispatcher: RpcDispatcher | None = None,
        caller: str | None = None,
        operator_tools: bool = False,
    ) -> None:
        if (
            sum(value is not None for value in (memory, memory_factory, rpc_dispatcher))
            != 1
        ):
            raise ValueError(
                "MCP server requires exactly one memory or broker dispatcher"
            )
        self.memory = memory
        self.memory_factory = memory_factory
        self.rpc_dispatcher = rpc_dispatcher
        self.caller = _validate_caller(caller)
        self.operator_tools = operator_tools
        self.tools = TOOLS if operator_tools else AGENT_TOOLS
        self.allowed_tool_names = frozenset(tool["name"] for tool in self.tools)

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        if (
            set(request) - {"jsonrpc", "id", "method", "params"}
            or request.get("jsonrpc") != "2.0"
            or not _valid_request_id(request_id, present="id" in request)
        ):
            return _rpc_error(None, -32600, "invalid JSON-RPC request")
        method = request.get("method")
        if not isinstance(method, str):
            return _rpc_error(request_id, -32600, "invalid JSON-RPC request")
        if "id" not in request:
            # Initialized, cancellation, and progress messages are notifications.
            return None
        if method == "initialize":
            return _rpc_result(
                request_id,
                {
                    # Never echo an arbitrary client value as if the server
                    # implemented it. MCP negotiation requires a version this
                    # server actually supports.
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "echo-veil", "version": __version__},
                    "instructions": SERVER_INSTRUCTIONS,
                },
            )
        if method == "ping":
            return _rpc_result(request_id, {})
        if method == "tools/list":
            return _rpc_result(request_id, {"tools": list(self.tools)})
        if method == "tools/call":
            return self._call_tool(request_id, request.get("params"))
        return _rpc_error(request_id, -32601, f"method not found: {method}")

    def _call_tool(self, request_id: Any, params: Any) -> dict[str, Any]:
        if not isinstance(params, Mapping) or not isinstance(params.get("name"), str):
            return _rpc_error(request_id, -32602, "tools/call requires a tool name")
        tool_name = str(params["name"])
        arguments = params.get("arguments", {})
        if not isinstance(arguments, Mapping):
            return _rpc_error(request_id, -32602, "tool arguments must be an object")
        try:
            if tool_name not in self.allowed_tool_names:
                raise ValueError("tool is not enabled for this MCP server")
            if self.rpc_dispatcher is not None:
                result = self.rpc_dispatcher(tool_name, arguments)
                if tool_name == "echo_veil_doctor":
                    result["mcp_profile_lease"] = "broker-persistent"
                    result["shared_profile_safe"] = True
            elif self.memory_factory is None:
                if self.memory is None:  # pragma: no cover - constructor invariant
                    raise RuntimeError("MCP memory adapter is unavailable")
                result = dispatch(
                    self.memory,
                    tool_name,
                    arguments,
                    caller=self.caller,
                )
            else:
                per_call_memory = self.memory_factory()
                try:
                    result = dispatch(
                        per_call_memory,
                        tool_name,
                        arguments,
                        caller=self.caller,
                    )
                finally:
                    per_call_memory.close()
                if tool_name == "echo_veil_doctor":
                    result["mcp_profile_lease"] = "per-tool-call"
                    result["shared_profile_safe"] = True
            if tool_name == "echo_veil_doctor":
                result["mcp_tool_profile"] = (
                    "operator" if self.operator_tools else "agent"
                )
        except Exception as exc:
            error = _public_error(exc)
            return _rpc_result(
                request_id,
                {
                    "content": [{"type": "text", "text": _json(error)}],
                    "structuredContent": error,
                    "isError": True,
                },
            )
        return _rpc_result(
            request_id,
            {
                "content": [{"type": "text", "text": _json(result)}],
                "structuredContent": result,
                "isError": False,
            },
        )


def run_mcp(
    memory: MemoryAdapter | None = None,
    *,
    memory_factory: MemoryFactory | None = None,
    rpc_dispatcher: RpcDispatcher | None = None,
    caller: str | None = None,
    operator_tools: bool = False,
) -> int:
    server = McpServer(
        memory,
        memory_factory=memory_factory,
        rpc_dispatcher=rpc_dispatcher,
        caller=caller,
        operator_tools=operator_tools,
    )
    while True:
        raw_line, oversized = _read_mcp_line(sys.stdin.buffer)
        if not raw_line:
            break
        if oversized:
            _write_response(_rpc_error(None, -32700, "request exceeds size limit"))
            continue
        if not raw_line.strip():
            continue
        try:
            parsed = strict_json_loads(raw_line)
            if not isinstance(parsed, Mapping):
                raise ValueError("request must be a JSON object")
            response = server.handle(parsed)
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            RecursionError,
            ValueError,
        ):
            response = _rpc_error(None, -32700, "invalid JSON request")
        if response is not None:
            _write_response(response)
    return 0


def _read_mcp_line(stream: BinaryIO) -> tuple[bytes, bool]:
    """Read and, when necessary, drain one request without unbounded buffering."""
    raw_line = stream.readline(MAX_REQUEST_BYTES + 1)
    if not raw_line:
        return b"", False
    oversized = len(raw_line) > MAX_REQUEST_BYTES
    while not raw_line.endswith(b"\n"):
        remainder = stream.readline(MAX_REQUEST_BYTES + 1)
        if not remainder:
            break
        oversized = True
        if remainder.endswith(b"\n"):
            break
    return raw_line, oversized


def run_rpc(
    memory: MemoryAdapter | None = None,
    *,
    rpc_dispatcher: RpcDispatcher | None = None,
    caller: str | None = None,
) -> int:
    if (memory is None) == (rpc_dispatcher is None):
        raise ValueError("RPC requires exactly one memory or broker dispatcher")
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds size limit")
    try:
        request = strict_json_loads(raw)
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise ValueError("invalid JSON request") from exc
    if not isinstance(request, Mapping):
        raise ValueError("request must be a JSON object")
    if set(request) - {"action", "arguments"}:
        raise ValueError("request contains unexpected fields")
    action = request.get("action")
    arguments = request.get("arguments", {})
    if rpc_dispatcher is not None:
        result = rpc_dispatcher(action, arguments)  # type: ignore[arg-type]
    else:
        assert memory is not None
        result = dispatch(memory, action, arguments, caller=caller)  # type: ignore[arg-type]
    print(_json(result))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="echo-veil-agent",
        description="Local encrypted Echo Veil adapter for agent runtimes.",
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=_optional_path_from_env("ECHO_VEIL_STATE_DIR"),
    )
    parser.add_argument(
        "--profile", default=os.environ.get("ECHO_VEIL_PROFILE", "default")
    )
    parser.add_argument(
        "--broker-socket",
        type=Path,
        default=_optional_path_from_env("ECHO_VEIL_BROKER_SOCKET"),
        help=(
            "owner-only Unix socket for a persistent serialized Echo broker; "
            "broker mode defaults to the selected profile directory"
        ),
    )
    parser.add_argument(
        "--scope",
        default=os.environ.get("ECHO_VEIL_SCOPE", "local-user"),
        help="authorization scope bound to this encrypted profile",
    )
    parser.add_argument(
        "--caller",
        default=os.environ.get("ECHO_VEIL_CALLER"),
        help=(
            "bounded host identity added to protected write provenance; bundled "
            "adapters set this explicitly"
        ),
    )
    parser.add_argument("--capacity", type=int, default=_capacity_from_env())
    parser.add_argument(
        "--embedder",
        choices=("hashing", "ollama"),
        default=os.environ.get("ECHO_VEIL_EMBEDDER", "hashing"),
        help="text embedding backend (bundled host configs use local Ollama)",
    )
    parser.add_argument(
        "--embedding-model",
        default=os.environ.get("ECHO_VEIL_EMBEDDING_MODEL", DEFAULT_OLLAMA_MODEL),
    )
    parser.add_argument(
        "--embedding-dimension",
        type=int,
        default=_int_from_env(
            "ECHO_VEIL_EMBEDDING_DIMENSION",
            DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
        ),
    )
    parser.add_argument(
        "--ollama-url",
        default=os.environ.get("ECHO_VEIL_OLLAMA_URL", DEFAULT_OLLAMA_URL),
    )
    parser.add_argument(
        "--embedding-timeout",
        type=float,
        default=_float_from_env(
            "ECHO_VEIL_EMBEDDING_TIMEOUT",
            DEFAULT_EMBEDDING_TIMEOUT_SECONDS,
        ),
    )
    parser.add_argument(
        "--profile-lock-timeout",
        type=float,
        default=_float_from_env(
            "ECHO_VEIL_PROFILE_LOCK_TIMEOUT",
            DEFAULT_PROFILE_LOCK_TIMEOUT_SECONDS,
        ),
        help="seconds to wait for another writer using the same profile",
    )
    parser.add_argument(
        "--availability-layer",
        action=argparse.BooleanOptionalAction,
        default=_bool_from_env("ECHO_VEIL_AVAILABILITY_LAYER", True),
        help=(
            "use explicit read-only keyed recall when local semantic embeddings "
            "are unavailable (enabled by default)"
        ),
    )
    parser.add_argument(
        "--operator-tools",
        action=argparse.BooleanOptionalAction,
        default=_bool_from_env("ECHO_VEIL_OPERATOR_TOOLS", False),
        help=(
            "expose key rotation and key retirement through MCP; disabled by "
            "default so ordinary agent hosts receive only the nine memory tools"
        ),
    )
    parser.add_argument("mode", choices=("rpc", "mcp", "doctor", "broker"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        caller = _validate_caller(args.caller)
        if args.mode == "broker":
            with _open_memory(args) as broker_memory:
                socket_path = (
                    default_broker_socket(broker_memory.profile_dir)
                    if args.broker_socket is None
                    else args.broker_socket.expanduser().absolute()
                )
                return _run_broker(broker_memory, socket_path)
        if args.broker_socket is not None:
            broker = BrokerClient(
                args.broker_socket,
                caller=caller or "local-cli",
                timeout_seconds=min(
                    float(args.profile_lock_timeout),
                    120.0,
                ),
            )
            if args.mode == "mcp":
                # A required MCP server must prove the broker is reachable at
                # startup, before the host is allowed to begin a model turn.
                from .agent_preflight import assert_doctor_ready

                assert_doctor_ready(
                    broker.call("doctor", {}),
                    expected_profile=args.profile,
                    expected_model=args.embedding_model,
                    expected_dimension=args.embedding_dimension,
                )
                return run_mcp(
                    rpc_dispatcher=broker.call,
                    caller=caller,
                    operator_tools=args.operator_tools,
                )
            if args.mode == "rpc":
                return run_rpc(rpc_dispatcher=broker.call, caller=caller)
            print(_json(broker.call("doctor", {})))
            return 0
        if args.mode == "mcp":
            # Validate the complete profile boundary at startup, then release
            # the writer lease. Each tool call reopens and closes the profile,
            # allowing multiple long-lived MCP transports in the same local
            # authorization domain to serialize on one protected authority.
            with _open_memory(args) as startup_probe:
                startup_probe.doctor()
            return run_mcp(
                memory_factory=lambda: _open_memory(args),
                caller=caller,
                operator_tools=args.operator_tools,
            )
        memory = _open_memory(args)
        with memory:
            if args.mode == "rpc":
                return run_rpc(memory, caller=caller)
            print(_json(memory.doctor()))
            return 0
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    except Exception as exc:
        print(_json(_public_error(exc)), file=sys.stderr)
        return 1


def _run_broker(memory: MemoryAdapter, socket_path: Path) -> int:
    """Serve a single profile until SIGINT/SIGTERM while preserving cleanup."""

    stop = threading.Event()
    previous_handlers: dict[int, Any] = {}

    def request_stop(_signum: int, _frame: object) -> None:
        stop.set()

    for signal_name in ("SIGINT", "SIGTERM"):
        number = getattr(signal, signal_name, None)
        if number is None:
            continue
        previous_handlers[int(number)] = signal.getsignal(number)
        signal.signal(number, request_stop)
    try:
        BrokerServer(
            socket_path,
            lambda action, arguments, caller: dispatch(
                memory,
                action,
                arguments,
                caller=caller,
            ),
        ).serve_forever(stop_event=stop)
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
    return 0


def _open_memory(args: argparse.Namespace) -> MemoryAdapter:
    try:
        embedder = _build_embedder(args)
        primary: BaseMemoryAdapter = AgentMemory(
            args.state_dir,
            profile=args.profile,
            scope=args.scope,
            capacity=args.capacity,
            embed=embedder,
            profile_lock_timeout_seconds=args.profile_lock_timeout,
        )
    except EmbeddingUnavailable:
        if args.embedder != "ollama" or not args.availability_layer:
            raise
        primary = AlwaysAvailableMemory(
            args.state_dir,
            profile=args.profile,
            scope=args.scope,
        )
    if (
        isinstance(primary, AgentMemory)
        and args.embedder == "ollama"
        and args.availability_layer
    ):
        return _RuntimeAvailabilityMemory(
            primary,
            args.state_dir,
            args.profile,
            args.scope,
        )
    return primary


def _capacity_from_env() -> int:
    return _int_from_env("ECHO_VEIL_CAPACITY", DEFAULT_CAPACITY)


def _optional_path_from_env(name: str) -> Path | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    if not raw.strip() or "\x00" in raw:
        raise ValueError(f"{name} must be a non-empty filesystem path")
    return Path(raw).expanduser()


def _int_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _float_from_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc


def _bool_from_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _build_embedder(args: argparse.Namespace) -> TextEmbedder:
    if args.embedder == "hashing":
        return HashingTextEmbedder()
    return OllamaTextEmbedder(
        model=args.embedding_model,
        base_url=args.ollama_url,
        dimension=args.embedding_dimension,
        timeout_seconds=args.embedding_timeout,
    )


def _require_only(arguments: Mapping[str, Any], allowed: set[str]) -> None:
    unknown = set(arguments) - allowed
    if unknown:
        raise ValueError(f"unexpected arguments: {', '.join(sorted(unknown))}")


def _validate_caller(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _CALLER_ID.fullmatch(value) is None:
        raise ValueError(
            "caller must be 1-64 letters, digits, dots, underscores, or hyphens"
        )
    return value


def _with_caller_provenance(
    value: object,
    caller: str | None,
) -> list[str] | tuple[str, ...] | None:
    clean_caller = _validate_caller(caller)
    if clean_caller is None:
        return value  # type: ignore[return-value]
    marker = f"caller:{clean_caller}"
    if value is None:
        return [marker]
    if not isinstance(value, (list, tuple)):
        raise TypeError("memory provenance must be a list or tuple")
    if marker in value:
        return value
    if len(value) >= 4:
        raise ValueError(
            "caller-attributed transports support at most 3 supplied provenance items"
        )
    return [marker, *value]


def _required_string(arguments: Mapping[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return value


def _rpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _valid_request_id(value: Any, *, present: bool) -> bool:
    if not present:
        return True
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, str):
        return 0 < len(value) <= 128
    return isinstance(value, (int, float)) and math.isfinite(float(value))


def _public_error(exc: Exception) -> dict[str, str]:
    allowed = isinstance(exc, (TypeError, ValueError, RuntimeError))
    message = str(exc).strip() if allowed else ""
    message = _ABSOLUTE_PATH.sub("<redacted-path>", message)
    message = _EMAIL.sub("<redacted-email>", message)
    message = _SECRET_ASSIGNMENT.sub(r"\1=<redacted>", message)
    message = _BEARER_TOKEN.sub("Bearer <redacted>", message)
    if (
        not message
        or len(message) > MAX_PUBLIC_ERROR_CHARS
        or any(
            (ord(character) < 32 and character not in "\t") or ord(character) == 127
            for character in message
        )
    ):
        message = "Echo Veil operation failed safely"
    return {"error": type(exc).__name__, "message": message}


def _write_response(response: Mapping[str, Any]) -> None:
    sys.stdout.write(_json(response) + "\n")
    sys.stdout.flush()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


if __name__ == "__main__":
    raise SystemExit(main())
