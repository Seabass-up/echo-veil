"""JSON-RPC and MCP entry points for supported agent integrations."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__
from ._json import strict_json_loads
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
    OllamaTextEmbedder,
    TextEmbedder,
)

MCP_PROTOCOL_VERSION = "2025-11-25"
MAX_REQUEST_BYTES = 1_048_576
MIN_HOST_RECALL_RESULTS = 2
SERVER_INSTRUCTIONS = (
    "Echo Veil is opt-in agent memory. Call echo_veil_remember only for durable "
    "facts the user intends to retain. Call echo_veil_recall before relying on "
    "stored facts, respect gated results, and use echo_veil_forget for explicit "
    "erasure. When ranking_ambiguous=true, preserve both leading candidates and "
    "do not collapse them into one asserted fact. A recall response with "
    "degraded=true came from the conservative read-only availability layer, not "
    "semantic or authoritative retrieval. Do not treat this local adapter as a "
    "production enclave."
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

    def remember(
        self,
        topic: str,
        payload: str,
        *,
        effective_at: float | None = None,
        supersedes: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        try:
            return self._memory.remember(
                topic,
                payload,
                effective_at=effective_at,
                supersedes=supersedes,
            )
        except EmbeddingUnavailable:
            return self._degrade().remember(
                topic,
                payload,
                effective_at=effective_at,
                supersedes=supersedes,
            )

    def recall(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float | None = None,
        allow_inferential: bool = False,
        as_of: float | None = None,
    ) -> dict[str, Any]:
        try:
            return self._memory.recall(
                query,
                top_k=top_k,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
            )
        except EmbeddingUnavailable:
            return self._degrade().recall(
                query,
                top_k=top_k,
                min_score=min_score,
                allow_inferential=allow_inferential,
                as_of=as_of,
            )

    def forget(self, vine_id: str) -> dict[str, Any]:
        return self._memory.forget(vine_id)

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

_ABSOLUTE_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/](?:[^\s\\/]+[\\/])+[^\s]+|/(?:[^\s/]+/)+[^\s]+)"
)
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_ -]?key|authorization|credential|password|private[_ -]?key|"
    r"secret|token)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+"
)
_BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+[A-Z0-9._~+/=-]+")
MAX_PUBLIC_ERROR_CHARS = 512


TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "echo_veil_remember",
        "description": (
            "Store one user-authorized durable memory in the local encrypted "
            "Echo Veil profile. Exact retries are deduplicated."
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
                    "maxLength": 100000,
                    "description": "Authorized memory content to encrypt and retain.",
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
        "name": "echo_veil_recall",
        "description": (
            "Recall relevant local Echo Veil memories and advance their decay "
            "lifecycle. During an embedding outage, an explicitly marked read-only "
            "availability layer can return only strong keyed lexical matches. "
            "Payloads are withheld when confidence policy gates them. Preserve "
            "both leading results when ranking_ambiguous=true; degraded results "
            "are neither semantic nor authoritative."
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


def dispatch(
    memory: MemoryAdapter, action: str, arguments: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(action, str):
        raise TypeError("action must be a string")
    if not isinstance(arguments, Mapping):
        raise TypeError("arguments must be an object")
    supplied = dict(arguments)
    if action in {"remember", "echo_veil_remember"}:
        _require_only(supplied, {"topic", "payload", "effective_at", "supersedes"})
        return memory.remember(
            topic=_required_string(supplied, "topic"),
            payload=_required_string(supplied, "payload"),
            effective_at=supplied.get("effective_at"),  # type: ignore[arg-type]
            supersedes=supplied.get("supersedes"),  # type: ignore[arg-type]
        )
    if action in {"recall", "echo_veil_recall"}:
        _require_only(
            supplied,
            {"query", "top_k", "min_score", "allow_inferential", "as_of"},
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
        )
        response["requested_top_k"] = requested_top_k
        response["effective_top_k"] = effective_top_k
        response["ambiguity_candidates_preserved"] = effective_top_k >= 2
        return response
    if action in {"forget", "echo_veil_forget"}:
        _require_only(supplied, {"vine_id"})
        return memory.forget(_required_string(supplied, "vine_id"))
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
    def __init__(self, memory: MemoryAdapter) -> None:
        self.memory = memory

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
            return _rpc_result(request_id, {"tools": list(TOOLS)})
        if method == "tools/call":
            return self._call_tool(request_id, request.get("params"))
        return _rpc_error(request_id, -32601, f"method not found: {method}")

    def _call_tool(self, request_id: Any, params: Any) -> dict[str, Any]:
        if not isinstance(params, Mapping) or not isinstance(params.get("name"), str):
            return _rpc_error(request_id, -32602, "tools/call requires a tool name")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, Mapping):
            return _rpc_error(request_id, -32602, "tool arguments must be an object")
        try:
            result = dispatch(self.memory, str(params["name"]), arguments)
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


def run_mcp(memory: MemoryAdapter) -> int:
    server = McpServer(memory)
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


def run_rpc(memory: MemoryAdapter) -> int:
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
    result = dispatch(memory, action, arguments)  # type: ignore[arg-type]
    print(_json(result))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="echo-veil-agent",
        description="Local encrypted Echo Veil adapter for agent runtimes.",
    )
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument(
        "--profile", default=os.environ.get("ECHO_VEIL_PROFILE", "default")
    )
    parser.add_argument(
        "--scope",
        default=os.environ.get("ECHO_VEIL_SCOPE", "local-user"),
        help="authorization scope bound to this encrypted profile",
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
    parser.add_argument("mode", choices=("rpc", "mcp", "doctor"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
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
        memory: MemoryAdapter = (
            _RuntimeAvailabilityMemory(
                primary,
                args.state_dir,
                args.profile,
                args.scope,
            )
            if (
                isinstance(primary, AgentMemory)
                and args.embedder == "ollama"
                and args.availability_layer
            )
            else primary
        )
        with memory:
            if args.mode == "mcp":
                return run_mcp(memory)
            if args.mode == "rpc":
                return run_rpc(memory)
            print(_json(memory.doctor()))
            return 0
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    except Exception as exc:
        print(_json(_public_error(exc)), file=sys.stderr)
        return 1


def _capacity_from_env() -> int:
    return _int_from_env("ECHO_VEIL_CAPACITY", DEFAULT_CAPACITY)


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
