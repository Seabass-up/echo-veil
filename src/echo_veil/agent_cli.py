"""JSON-RPC and MCP entry points for supported agent integrations."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__
from .agent_memory import AgentMemory, DEFAULT_CAPACITY

MCP_PROTOCOL_VERSION = "2025-11-25"
MAX_REQUEST_BYTES = 1_048_576
SERVER_INSTRUCTIONS = (
    "Echo Veil is opt-in agent memory. Call echo_veil_remember only for durable "
    "facts the user intends to retain. Call echo_veil_recall before relying on "
    "stored facts, respect gated results, and use echo_veil_forget for explicit "
    "erasure. Do not treat this local adapter as a production enclave."
)


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
                    "description": "Short, non-secret label for the memory.",
                },
                "payload": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 100000,
                    "description": "Authorized memory content to encrypt and retain.",
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
            "lifecycle. Payloads are withheld when confidence policy gates them."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 20000},
                "top_k": {"type": "integer", "minimum": 1, "maximum": 20},
                "min_score": {"type": "number", "minimum": 0, "maximum": 1},
                "allow_inferential": {
                    "type": "boolean",
                    "description": (
                        "Use only after the user explicitly authorizes inferential recall."
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
)


def dispatch(
    memory: AgentMemory, action: str, arguments: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(action, str):
        raise TypeError("action must be a string")
    if not isinstance(arguments, Mapping):
        raise TypeError("arguments must be an object")
    supplied = dict(arguments)
    if action in {"remember", "echo_veil_remember"}:
        _require_only(supplied, {"topic", "payload"})
        return memory.remember(
            topic=_required_string(supplied, "topic"),
            payload=_required_string(supplied, "payload"),
        )
    if action in {"recall", "echo_veil_recall"}:
        _require_only(supplied, {"query", "top_k", "min_score", "allow_inferential"})
        return memory.recall(
            query=_required_string(supplied, "query"),
            top_k=supplied.get("top_k", 5),  # type: ignore[arg-type]
            min_score=supplied.get("min_score", 0.35),  # type: ignore[arg-type]
            allow_inferential=supplied.get("allow_inferential", False),  # type: ignore[arg-type]
        )
    if action in {"forget", "echo_veil_forget"}:
        _require_only(supplied, {"vine_id"})
        return memory.forget(_required_string(supplied, "vine_id"))
    if action in {"doctor", "echo_veil_doctor"}:
        _require_only(supplied, set())
        return memory.doctor()
    raise ValueError(f"unknown Echo Veil action: {action}")


class McpServer:
    def __init__(self, memory: AgentMemory) -> None:
        self.memory = memory

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        method = request.get("method")
        if not isinstance(method, str):
            return _rpc_error(request_id, -32600, "invalid JSON-RPC request")
        if request_id is None:
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
            error = {"error": type(exc).__name__, "message": str(exc)}
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


def run_mcp(memory: AgentMemory) -> int:
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
            parsed = json.loads(raw_line)
            if not isinstance(parsed, Mapping):
                raise ValueError("request must be a JSON object")
            response = server.handle(parsed)
        except (json.JSONDecodeError, ValueError) as exc:
            response = _rpc_error(None, -32700, f"invalid JSON: {exc}")
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


def run_rpc(memory: AgentMemory) -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds size limit")
    request = json.loads(raw)
    if not isinstance(request, Mapping):
        raise ValueError("request must be a JSON object")
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
    parser.add_argument("--capacity", type=int, default=_capacity_from_env())
    parser.add_argument("mode", choices=("rpc", "mcp", "doctor"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with AgentMemory(
            args.state_dir,
            profile=args.profile,
            capacity=args.capacity,
        ) as memory:
            if args.mode == "mcp":
                return run_mcp(memory)
            if args.mode == "rpc":
                return run_rpc(memory)
            print(_json(memory.doctor()))
            return 0
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    except Exception as exc:
        print(
            _json({"error": type(exc).__name__, "message": str(exc)}), file=sys.stderr
        )
        return 1


def _capacity_from_env() -> int:
    raw = os.environ.get("ECHO_VEIL_CAPACITY")
    if raw is None:
        return DEFAULT_CAPACITY
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError("ECHO_VEIL_CAPACITY must be an integer") from exc


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


def _write_response(response: Mapping[str, Any]) -> None:
    sys.stdout.write(_json(response) + "\n")
    sys.stdout.flush()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


if __name__ == "__main__":
    raise SystemExit(main())
