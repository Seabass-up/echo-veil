#!/usr/bin/env python3
"""Review and migrate one bounded plaintext host-memory catalog into Echo Veil."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from echo_veil.agent_memory import (
    AgentMemory,
    AlwaysAvailableMemory,
    DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    OllamaTextEmbedder,
    default_state_dir,
)


SCHEMA_VERSION = 1
MAX_SOURCE_BYTES = 1_048_576
MAX_SOURCE_RECORDS = 200
MAX_SHORT_TERM_CHARS = 12_000
MAX_SEED_CRYSTAL_CHARS = 2_000
MAX_VERIFIER_REQUEST_BYTES = 32_768
MAX_VERIFIER_RESPONSE_BYTES = 4_096
VERIFIER_TIMEOUT_SECONDS = 30.0
IMPORT_CONFIRMATION = "IMPORT_REVIEWED_HOST_MEMORY"
RETIRE_CONFIRMATION = "RETIRE_VERIFIED_PLAINTEXT_SOURCE"
_CALLER = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")
_LOCAL_PATH = re.compile(
    r"(?:/Users/[^/\s]+/|/home/[^/\s]+/|[A-Za-z]:[\\/]Users[\\/][^\\/\s]+[\\/])"  # privacy-scan:allow -- detector definition
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_ -]?key|access[_ -]?token|password|private[_ -]?key|secret)"
    r"\b\s*(?::|=)\s*\S+"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_TRANSCRIPT_ROLE = re.compile(r"(?im)(?:^|\s)(?:user|assistant|system|tool)\s*:")


class HostMemoryMigrationError(RuntimeError):
    """Bounded operator-facing migration failure."""


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    digest: str


@dataclass(frozen=True, slots=True)
class ReviewedRecord:
    index: int
    payload: str
    review_reasons: tuple[str, ...]
    ineligible_reasons: tuple[str, ...]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Dry-run, import, verify, and optionally retire one JSON-list host "
            "memory catalog without printing its payloads."
        )
    )
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--profile", default="echo-universal-qwen3-v1")
    parser.add_argument("--scope", default="local-user")
    parser.add_argument("--caller", required=True)
    parser.add_argument("--embedding-model", default=DEFAULT_OLLAMA_MODEL)
    parser.add_argument(
        "--embedding-dimension",
        type=int,
        default=DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    )
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument(
        "--confirm",
        metavar="PHRASE",
        help=f"write only when exactly {IMPORT_CONFIRMATION!r}",
    )
    parser.add_argument(
        "--allow-review-required",
        action="store_true",
        help="import records whose dry run flagged paths, credentials, or density",
    )
    parser.add_argument(
        "--retire-source",
        action="store_true",
        help="logically unlink the plaintext source only after fresh-process verification",
    )
    parser.add_argument(
        "--retire-confirm",
        metavar="PHRASE",
        help=f"retire only when exactly {RETIRE_CONFIRMATION!r}",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        help="hash-only receipt path; defaults beside the source",
    )
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    caller = _validate_caller(args.caller)
    source, raw, identity = _read_source(args.source)
    records = _decode_and_review(raw)
    unique_records = _unique_records(records)
    report = _review_report(
        records,
        unique_records,
        identity,
        caller=caller,
        profile=str(args.profile),
        scope=str(args.scope),
    )
    if args.confirm is None:
        if args.retire_source or args.retire_confirm is not None:
            raise HostMemoryMigrationError(
                "source retirement requires a confirmed protected import"
            )
        return report
    if args.confirm != IMPORT_CONFIRMATION:
        raise HostMemoryMigrationError("host-memory import confirmation is invalid")

    ineligible = [record for record in records if record.ineligible_reasons]
    if ineligible:
        raise HostMemoryMigrationError(
            "source contains ineligible records; protected import was not started"
        )
    review_required = [record for record in records if record.review_reasons]
    if review_required and args.allow_review_required is not True:
        raise HostMemoryMigrationError(
            "source contains review-required records; inspect the dry-run indices"
        )
    if args.retire_source and args.retire_confirm != RETIRE_CONFIRMATION:
        raise HostMemoryMigrationError(
            "plaintext-source retirement confirmation is invalid"
        )
    if not args.retire_source and args.retire_confirm is not None:
        raise HostMemoryMigrationError(
            "retirement confirmation requires --retire-source"
        )

    topic = f"host import · {caller} · {identity.digest[:12]}"
    try:
        embedder = OllamaTextEmbedder(
            model=args.embedding_model,
            base_url=args.ollama_url,
            dimension=args.embedding_dimension,
        )
    except Exception as exc:
        raise HostMemoryMigrationError(
            "embedding service is unavailable; plaintext source was retained"
        ) from exc
    created_ids: list[str] = []
    created_count = 0
    duplicate_count = 0
    try:
        with AgentMemory(
            args.state_dir,
            profile=args.profile,
            scope=args.scope,
            embed=embedder,
        ) as memory:
            try:
                for record in unique_records:
                    result = memory.remember(
                        topic,
                        record.payload,
                        layer="short_term",
                        provenance=[
                            f"caller:{caller}",
                            "migration:explicit-host-import",
                        ],
                    )
                    if result.get("created") is True:
                        created_ids.append(str(result["vine_id"]))
                        created_count += 1
                    else:
                        duplicate_count += 1
            except Exception:
                for vine_id in reversed(created_ids):
                    memory.forget(vine_id)
                raise
    except Exception as exc:
        raise HostMemoryMigrationError(
            "protected host-memory import failed; plaintext source was retained"
        ) from exc

    try:
        verification = _verify_fresh_process(
            args,
            embedder=embedder,
            topic=topic,
            expected=unique_records,
        )
    except Exception as exc:
        raise HostMemoryMigrationError(
            "fresh-process protected verification failed; protected writes and "
            "the plaintext source were retained for an idempotent retry"
        ) from exc

    receipt_path = _receipt_path(source, args.receipt)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "state": (
            "verified_pending_retirement"
            if args.retire_source
            else "verified_source_retained"
        ),
        "source_digest": f"sha256:{identity.digest}",
        "source_records": len(records),
        "unique_records": len(unique_records),
        "created_records": created_count,
        "duplicate_records": duplicate_count,
        "review_required_records": len(review_required),
        "profile": str(args.profile),
        "scope": str(args.scope),
        "caller": caller,
        "memory_layer": "short_term",
        "all_records_shielded": verification["all_records_shielded"],
        "fresh_process_verified": True,
        "plaintext_export_created": False,
        "plaintext_source_retired": False,
        "retirement_is_secure_erase": False,
        "completed_at": int(time.time()),
    }
    _write_receipt(receipt_path, receipt)

    if args.retire_source:
        _retire_source(source, identity)
        receipt["state"] = "retired"
        receipt["plaintext_source_retired"] = True
        _write_receipt(receipt_path, receipt)

    return {
        **report,
        "mode": "confirmed_import",
        "protected_write_attempted": True,
        "created_records": created_count,
        "duplicate_records": duplicate_count,
        "fresh_process_verified": True,
        "all_records_shielded": verification["all_records_shielded"],
        "plaintext_export_created": False,
        "plaintext_source_retired": bool(args.retire_source),
        "retirement_is_secure_erase": False,
        "receipt_written": True,
    }


def _validate_caller(value: object) -> str:
    clean = str(value or "").strip().casefold()
    if not _CALLER.fullmatch(clean):
        raise HostMemoryMigrationError(
            "caller must use 1-64 lowercase letters, numbers, dots, underscores, or hyphens"
        )
    return clean


def _read_source(path: Path) -> tuple[Path, bytes, SourceIdentity]:
    source = path.expanduser().absolute()
    _validate_parent(source.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise HostMemoryMigrationError(
            "plaintext source could not be opened safely"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise HostMemoryMigrationError("plaintext source must be a regular file")
        if os.name != "nt":
            if before.st_uid != os.getuid():
                raise HostMemoryMigrationError(
                    "plaintext source must be owned by the current user"
                )
            if stat.S_IMODE(before.st_mode) & 0o077:
                raise HostMemoryMigrationError(
                    "plaintext source permissions must be owner-only"
                )
        if before.st_size < 2 or before.st_size > MAX_SOURCE_BYTES:
            raise HostMemoryMigrationError("plaintext source size is outside policy")
        chunks: list[bytes] = []
        remaining = MAX_SOURCE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) > MAX_SOURCE_BYTES
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(raw) != before.st_size
    ):
        raise HostMemoryMigrationError("plaintext source changed during inspection")
    identity = SourceIdentity(
        device=before.st_dev,
        inode=before.st_ino,
        size=before.st_size,
        modified_ns=before.st_mtime_ns,
        digest=hashlib.sha256(raw).hexdigest(),
    )
    return source, raw, identity


def _validate_parent(parent: Path) -> None:
    current = parent
    while True:
        if current.is_symlink():
            raise HostMemoryMigrationError(
                "source and receipt paths must not contain symlink components"
            )
        if current == current.parent:
            break
        current = current.parent
    if not parent.is_dir():
        raise HostMemoryMigrationError("source parent must be a real directory")
    if os.name != "nt":
        metadata = parent.stat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise HostMemoryMigrationError(
                "source parent must be current-user-owned and not group/world writable"
            )


def _decode_and_review(raw: bytes) -> list[ReviewedRecord]:
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HostMemoryMigrationError(
            "plaintext source must be valid UTF-8 JSON"
        ) from exc
    if not isinstance(decoded, list) or not 1 <= len(decoded) <= MAX_SOURCE_RECORDS:
        raise HostMemoryMigrationError(
            f"plaintext source must contain 1-{MAX_SOURCE_RECORDS} JSON string records"
        )
    records: list[ReviewedRecord] = []
    for index, value in enumerate(decoded):
        if not isinstance(value, str):
            raise HostMemoryMigrationError(
                "plaintext source records must all be strings"
            )
        payload = value.strip()
        review_reasons: list[str] = []
        ineligible_reasons: list[str] = []
        if (
            not payload
            or len(payload) > MAX_SHORT_TERM_CHARS
            or not payload.isprintable()
        ):
            ineligible_reasons.append("invalid_or_oversized_short_term_record")
        if len(_TRANSCRIPT_ROLE.findall(payload)) >= 2:
            ineligible_reasons.append("raw_transcript")
        if len(payload) > MAX_SEED_CRYSTAL_CHARS:
            review_reasons.append("dense_seed_crystal")
        if _LOCAL_PATH.search(payload):
            review_reasons.append("developer_machine_path")
        if _CREDENTIAL_ASSIGNMENT.search(payload) or _PRIVATE_KEY.search(payload):
            review_reasons.append("credential_like_content")
        records.append(
            ReviewedRecord(
                index=index,
                payload=payload,
                review_reasons=tuple(review_reasons),
                ineligible_reasons=tuple(ineligible_reasons),
            )
        )
    return records


def _unique_records(records: list[ReviewedRecord]) -> list[ReviewedRecord]:
    seen: set[str] = set()
    unique: list[ReviewedRecord] = []
    for record in records:
        digest = hashlib.sha256(record.payload.encode("utf-8")).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        unique.append(record)
    return unique


def _review_report(
    records: list[ReviewedRecord],
    unique_records: list[ReviewedRecord],
    identity: SourceIdentity,
    *,
    caller: str,
    profile: str,
    scope: str,
) -> dict[str, Any]:
    review = [record for record in records if record.review_reasons]
    ineligible = [record for record in records if record.ineligible_reasons]
    review_reason_counts = _reason_counts(
        reason for record in review for reason in record.review_reasons
    )
    ineligible_reason_counts = _reason_counts(
        reason for record in ineligible for reason in record.ineligible_reasons
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "dry_run",
        "source_digest": f"sha256:{identity.digest}",
        "source_records": len(records),
        "unique_records": len(unique_records),
        "duplicate_source_records": len(records) - len(unique_records),
        "eligible_records": len(records) - len(ineligible),
        "review_required_records": len(review),
        "review_required_indices": [record.index for record in review],
        "review_reason_counts": review_reason_counts,
        "ineligible_records": len(ineligible),
        "ineligible_indices": [record.index for record in ineligible],
        "ineligible_reason_counts": ineligible_reason_counts,
        "profile": profile,
        "scope": scope,
        "caller": caller,
        "target_layer": "short_term",
        "protected_write_attempted": False,
        "fresh_process_verified": False,
        "plaintext_export_created": False,
        "plaintext_source_retired": False,
        "payloads_in_report": False,
    }


def _reason_counts(reasons: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for reason in reasons:
        counts[str(reason)] = counts.get(str(reason), 0) + 1
    return dict(sorted(counts.items()))


def _verify_fresh_process(
    args: argparse.Namespace,
    *,
    embedder: Any,
    topic: str,
    expected: list[ReviewedRecord],
) -> dict[str, Any]:
    with AgentMemory(
        args.state_dir,
        profile=args.profile,
        scope=args.scope,
        embed=embedder,
    ) as memory:
        records = memory.list_memories(
            limit=MAX_SOURCE_RECORDS,
            layers=["short_term"],
            topic_prefix=topic,
        )
        doctor = memory.doctor()
    expected_payloads = {record.payload for record in expected}
    actual_payloads = {
        str(record["payload"]) for record in records if record.get("topic") == topic
    }
    if actual_payloads != expected_payloads:
        raise HostMemoryMigrationError(
            "fresh-process protected inventory does not match the reviewed source"
        )
    if not records or any(
        record.get("layer_contract_protected") is not True
        or record.get("memory_layer") != "short_term"
        for record in records
    ):
        raise HostMemoryMigrationError(
            "fresh-process memory-layer protection verification failed"
        )
    memory_layers = doctor.get("memory_layers")
    if (
        not isinstance(memory_layers, dict)
        or memory_layers.get("all_records_shielded") is not True
    ):
        raise HostMemoryMigrationError("fresh-instance shield verification failed")
    _verify_in_child_process(
        args,
        topic=topic,
        expected=expected,
    )
    return {"all_records_shielded": True}


def _verify_in_child_process(
    args: argparse.Namespace,
    *,
    topic: str,
    expected: list[ReviewedRecord],
) -> None:
    state_dir = (
        default_state_dir()
        if args.state_dir is None
        else Path(args.state_dir).expanduser()
    ).absolute()
    request = {
        "schema_version": SCHEMA_VERSION,
        "state_dir": str(state_dir),
        "profile": str(args.profile),
        "scope": str(args.scope),
        "topic": topic,
        "expected_payload_hashes": sorted(
            hashlib.sha256(record.payload.encode("utf-8")).hexdigest()
            for record in expected
        ),
    }
    encoded = json.dumps(
        request,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_VERIFIER_REQUEST_BYTES:
        raise HostMemoryMigrationError(
            "fresh-process verification request exceeds policy"
        )
    environment = {
        "PATH": os.defpath,
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
    }
    try:
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--_verify-child"],
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=VERIFIER_TIMEOUT_SECONDS,
            check=False,
            shell=False,
            close_fds=True,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostMemoryMigrationError(
            "fresh-process protected verification could not run"
        ) from exc
    if completed.returncode != 0 or len(completed.stdout) > MAX_VERIFIER_RESPONSE_BYTES:
        raise HostMemoryMigrationError("fresh-process protected verification failed")
    try:
        response = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HostMemoryMigrationError(
            "fresh-process protected verification returned an invalid receipt"
        ) from exc
    if response != {
        "all_records_shielded": True,
        "fresh_process_verified": True,
        "record_count": len(expected),
        "schema_version": SCHEMA_VERSION,
    }:
        raise HostMemoryMigrationError(
            "fresh-process protected verification returned an invalid receipt"
        )


def _run_verifier_child() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_VERIFIER_REQUEST_BYTES + 1)
        if not raw or len(raw) > MAX_VERIFIER_REQUEST_BYTES:
            raise HostMemoryMigrationError("invalid verifier request")
        request = json.loads(raw.decode("utf-8"))
        if (
            not isinstance(request, dict)
            or request.get("schema_version") != SCHEMA_VERSION
        ):
            raise HostMemoryMigrationError("invalid verifier request")
        state_dir = request.get("state_dir")
        profile = request.get("profile")
        scope = request.get("scope")
        topic = request.get("topic")
        expected_hashes = request.get("expected_payload_hashes")
        if (
            not isinstance(state_dir, str)
            or not state_dir
            or not isinstance(profile, str)
            or not profile
            or not isinstance(scope, str)
            or not scope
            or not isinstance(topic, str)
            or not topic
            or not isinstance(expected_hashes, list)
            or not 1 <= len(expected_hashes) <= MAX_SOURCE_RECORDS
            or any(
                not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None
                for item in expected_hashes
            )
            or len(set(expected_hashes)) != len(expected_hashes)
        ):
            raise HostMemoryMigrationError("invalid verifier request")
        with AlwaysAvailableMemory(
            state_dir,
            profile=profile,
            scope=scope,
            reason="migration_fresh_process_verification",
        ) as memory:
            records = memory.list_memories(
                limit=MAX_SOURCE_RECORDS,
                layers=["short_term"],
                topic_prefix=topic,
            )
            doctor = memory.doctor()
        actual_hashes = sorted(
            hashlib.sha256(str(record["payload"]).encode("utf-8")).hexdigest()
            for record in records
            if record.get("topic") == topic
        )
        memory_layers = doctor.get("memory_layers")
        if (
            actual_hashes != expected_hashes
            or not isinstance(memory_layers, dict)
            or memory_layers.get("all_records_shielded") is not True
            or any(
                record.get("layer_contract_protected") is not True
                or record.get("memory_layer") != "short_term"
                for record in records
            )
        ):
            raise HostMemoryMigrationError("verification mismatch")
        print(
            json.dumps(
                {
                    "all_records_shielded": True,
                    "fresh_process_verified": True,
                    "record_count": len(records),
                    "schema_version": SCHEMA_VERSION,
                },
                sort_keys=True,
            )
        )
        return 0
    except Exception:
        print(
            json.dumps(
                {
                    "error": "fresh_process_verification_failed",
                    "payloads_in_report": False,
                },
                sort_keys=True,
            )
        )
        return 1


def _receipt_path(source: Path, configured: Path | None) -> Path:
    receipt = (
        source.with_name(f"{source.name}.echo-veil-receipt.json")
        if configured is None
        else configured.expanduser().absolute()
    )
    if receipt == source:
        raise HostMemoryMigrationError("receipt path must differ from the source")
    _validate_parent(receipt.parent)
    if receipt.exists() and receipt.is_symlink():
        raise HostMemoryMigrationError("receipt path must not be a symlink")
    return receipt


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    encoded = (
        json.dumps(
            receipt,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise HostMemoryMigrationError(
            "hash-only receipt could not be written"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _retire_source(source: Path, expected: SourceIdentity) -> None:
    _, _, current = _read_source(source)
    if current != expected:
        raise HostMemoryMigrationError(
            "plaintext source changed after protected verification"
        )
    try:
        metadata = source.lstat()
        if (
            metadata.st_dev != expected.device
            or metadata.st_ino != expected.inode
            or metadata.st_size != expected.size
            or metadata.st_mtime_ns != expected.modified_ns
        ):
            raise HostMemoryMigrationError(
                "plaintext source identity changed before retirement"
            )
        source.unlink()
        _fsync_directory(source.parent)
    except OSError as exc:
        raise HostMemoryMigrationError(
            "verified plaintext source could not be retired"
        ) from exc


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("receipt write made no progress")
        offset += written


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    actual_argv = sys.argv[1:] if argv is None else argv
    if actual_argv == ["--_verify-child"]:
        return _run_verifier_child()
    try:
        report = run(build_parser().parse_args(actual_argv))
    except Exception as exc:
        message = (
            str(exc)
            if isinstance(exc, HostMemoryMigrationError)
            else "host memory migration failed without changing the plaintext source"
        )
        print(
            json.dumps(
                {
                    "error": type(exc).__name__,
                    "message": message,
                    "payloads_in_report": False,
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
