#!/usr/bin/env python3
"""Pin v0.7 consumers and build real mixed/v3 compatibility responses."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

import numpy as np

from echo_veil.agent_cli import dispatch
from echo_veil.agent_memory import AgentMemory
from echo_veil.preflight_receipt import PREFLIGHT_RECEIPT_SCHEMA


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "protocol" / "n-minus-one-v0.7.0.json"
BUNDLE_SCHEMA = "echo-veil-n-minus-one-bundle-v1"
MANIFEST_SCHEMA = "echo-veil-n-minus-one-manifest-v1"
LEGACY_RELEASE = "0.7.0"
LEGACY_COMMIT = "e94be9e649048273ab74eb1150e65ac9481596d9"
CANONICAL_PROFILE = "echo-universal-qwen3-v1"
CANONICAL_SCOPE = "local-user"
QUERY = "Which protected compatibility records are current?"
MAX_BUNDLE_BYTES = 2_000_000
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class _SemanticEmbedder:
    identity = (
        "ollama:qwen3-embedding:latest@sha256:"
        + "a" * 64
        + ":dimension:1024:instruction:"
        + "b" * 64
    )
    name = "ollama"
    model = "qwen3-embedding:latest"
    dimension = 1024
    semantic = True
    default_min_score = 0.44

    def embed_document(self, _text: str) -> np.ndarray:
        vector = np.zeros(self.dimension, dtype=np.float64)
        vector[0] = 1.0
        return vector

    def embed_query(self, text: str) -> np.ndarray:
        return self.embed_document(text)

    def embed_retrieval_queries(self, text: str) -> tuple[np.ndarray, np.ndarray]:
        vector = self.embed_query(text)
        return vector, vector.copy()


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("compatibility document must be an object")
    return value


def load_manifest() -> dict[str, Any]:
    manifest = _load_object(MANIFEST_PATH)
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("release") != LEGACY_RELEASE
        or manifest.get("commit") != LEGACY_COMMIT
    ):
        raise ValueError("N-1 compatibility manifest identity is invalid")
    consumers = manifest.get("consumers")
    if not isinstance(consumers, dict) or not consumers:
        raise ValueError("N-1 compatibility consumers are unavailable")
    return manifest


def _safe_legacy_file(source: Path, relative: str) -> Path:
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("N-1 manifest contains an unsafe file name")
    candidate = source / relative_path
    if candidate.is_symlink():
        raise ValueError("N-1 consumer artifact must not be a symbolic link")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(source)
    except ValueError as exc:
        raise ValueError("N-1 consumer artifact escapes the pinned source") from exc
    if not resolved.is_file() or resolved.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("N-1 consumer artifact is unavailable or oversized")
    return resolved


def verify_legacy_source(source: Path) -> dict[str, object]:
    root = source.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("legacy source must be a real directory")
    manifest = load_manifest()
    verified: list[str] = []
    for consumer in manifest["consumers"].values():
        if not isinstance(consumer, dict) or not isinstance(
            consumer.get("files"), dict
        ):
            raise ValueError("N-1 consumer manifest entry is invalid")
        for relative, expected in consumer["files"].items():
            if not isinstance(relative, str) or not isinstance(expected, str):
                raise ValueError("N-1 consumer digest entry is invalid")
            if _SHA256.fullmatch(expected) is None:
                raise ValueError("N-1 consumer digest is invalid")
            artifact = _safe_legacy_file(root, relative)
            actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if not hmac.compare_digest(actual, expected):
                raise ValueError("N-1 consumer artifact digest mismatch")
            verified.append(relative)
    project = _safe_legacy_file(root, "pyproject.toml").read_text(encoding="utf-8")
    if f'version = "{LEGACY_RELEASE}"' not in project:
        raise ValueError("legacy source release is not v0.7.0")
    return {
        "commit": LEGACY_COMMIT,
        "files_verified": len(set(verified)),
        "release": LEGACY_RELEASE,
    }


def _legacy_preflight(memory: AgentMemory, host: str) -> dict[str, Any]:
    response = dispatch(
        memory,
        "preflight",
        {
            "query": QUERY,
            "expected_profile": CANONICAL_PROFILE,
            "expected_scope": CANONICAL_SCOPE,
            "expected_model": "qwen3-embedding:latest",
            "expected_dimension": 1024,
            "query_source": "current_user_prompt",
        },
        caller=host,
    )
    if "record_envelope" in response or "record-envelope" in json.dumps(response):
        raise RuntimeError("storage format leaked through legacy preflight")
    return response


def _state_bundle(memory: AgentMemory, state: str) -> dict[str, Any]:
    legacy = {
        host: _legacy_preflight(memory, host)
        for host in (
            "aip",
            "claude-code",
            "codex",
            "droid",
            "hermes",
            "openclaw",
            "opencode",
        )
    }
    doctor = dispatch(memory, "doctor", {}, caller="pi")
    recall = dispatch(
        memory,
        "recall",
        {"query": QUERY, "top_k": 2, "allow_inferential": False},
        caller="pi",
    )
    signed = dispatch(
        memory,
        "preflight_v2",
        {
            "query": QUERY,
            "expected_profile": CANONICAL_PROFILE,
            "expected_scope": CANONICAL_SCOPE,
            "query_source": "current_user_prompt",
            "session_id": f"n-minus-one-{state}",
            "turn_id": f"turn-{state}",
            "model_digest": "sha256:" + "1" * 64,
            "tool_manifest_digest": "sha256:" + "2" * 64,
            "artifact_authority_id": "sha256:" + "3" * 64,
        },
        caller="codex",
    )
    if signed.get("schema") != PREFLIGHT_RECEIPT_SCHEMA:
        raise RuntimeError("current signed preflight schema changed unexpectedly")
    if "record_envelope" in signed or "record-envelope" in json.dumps(signed):
        raise RuntimeError("storage format leaked through signed preflight")
    return {
        "doctor": doctor,
        "legacy_preflight": legacy,
        "pi_recall": recall,
        "signed_preflight_v2": signed,
        "state": state,
    }


def build_bundle(state_dir: Path) -> dict[str, Any]:
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    with AgentMemory(
        state_dir,
        profile=CANONICAL_PROFILE,
        scope=CANONICAL_SCOPE,
        embed=_SemanticEmbedder(),
    ) as memory:
        for index in range(4):
            memory.remember(
                "compatibility record",
                f"Protected synthetic compatibility record {index} remains current.",
                provenance=["qualification:n-minus-one"],
            )
        pre_migration = memory.backup_create(state_dir / ".pre-v3-backup")
        mixed = memory.migrate_record_envelope_v3(
            confirm=True,
            batch_size=2,
            verified_backup=pre_migration,
        )
        if mixed["state"] != "migrating" or mixed["remaining_v2_records"] < 1:
            raise RuntimeError("synthetic profile did not enter a mixed v2/v3 state")
        mixed_bundle = _state_bundle(memory, "mixed-v2-v3")
        for _attempt in range(32):
            migrated = memory.migrate_record_envelope_v3(confirm=True, batch_size=2)
            if migrated["state"] == "verified":
                break
        else:
            raise RuntimeError("record-envelope v3 migration did not converge")
        if migrated["preflight_protocol"] != "preflight_v2":
            raise RuntimeError("storage migration changed the preflight protocol")
        v3_bundle = _state_bundle(memory, "fully-v3")
    bundle = {
        "invariants": load_manifest()["invariants"],
        "legacy_release": LEGACY_RELEASE,
        "query": QUERY,
        "schema": BUNDLE_SCHEMA,
        "states": [mixed_bundle, v3_bundle],
    }
    encoded = json.dumps(bundle, ensure_ascii=True, sort_keys=True).encode("utf-8")
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise RuntimeError("N-1 compatibility bundle exceeds its size bound")
    return bundle


def _write_bundle(path: Path, bundle: dict[str, Any]) -> None:
    destination = path.resolve()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-source", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        verified = verify_legacy_source(args.legacy_source)
        report: dict[str, object] = {
            **verified,
            "schema": "echo-veil-n-minus-one-verification-v1",
        }
        if not args.verify_only:
            if args.output is None:
                raise ValueError("--output is required unless --verify-only is set")
            private_tmp = Path(
                "/private/tmp"
                if os.name == "posix" and Path("/private/tmp").is_dir()
                else "/tmp"
            )
            with tempfile.TemporaryDirectory(
                prefix="echo-veil-n-minus-one-",
                dir=private_tmp,
            ) as temporary:
                bundle = build_bundle(Path(temporary) / "state")
            _write_bundle(args.output, bundle)
            report["bundle_schema"] = BUNDLE_SCHEMA
            report["states"] = [item["state"] for item in bundle["states"]]
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": type(exc).__name__,
                    "message": "N-1 consumer verification failed",
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
