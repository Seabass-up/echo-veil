"""Durable, local-first host adapter for agent runtimes.

The core Echo Veil package deliberately leaves text embedding and authorized
payload storage to its host. Agent runtimes need a concrete implementation of
those responsibilities, so this module provides a small local adapter:

* deterministic hashing embeddings with no network dependency;
* AES-GCM protected Echo Veil anchors;
* a separate AES-GCM encrypted payload database; and
* confidence-gated recall across active and archived memory.

It is intended for one local operating-system user.  Multi-user authorization,
remote synchronization, and production enclave guarantees remain host duties.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
import stat
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import Any, cast

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from numpy.typing import NDArray

from .archive import TransactionalEvictionStore
from .confidence import classify
from .crypto_shield import AesGcmCryptoShield
from .oracle import GenerationGated, Oracle
from .persistence import SQLiteStore
from .workspace import WorkspaceConfig

DEFAULT_EMBEDDING_DIMENSION = 384
DEFAULT_CAPACITY = 400
MAX_TOPIC_CHARS = 512
MAX_PAYLOAD_CHARS = 100_000
MAX_QUERY_CHARS = 20_000
MAX_RECALL_RESULTS = 20
_PROFILE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_TOKEN_PATTERN = re.compile(r"[^\W_]+", re.UNICODE)


class HashingTextEmbedder:
    """Return stable local text vectors without a model download or API call.

    Token and adjacent-token features are hashed into a signed fixed-size
    vector.  This is useful for private, dependency-light integration testing
    and modest keyword-oriented recall.  It is not a substitute for a reviewed
    semantic embedding model on large or multilingual corpora.
    """

    def __init__(self, dimension: int = DEFAULT_EMBEDDING_DIMENSION) -> None:
        if isinstance(dimension, bool) or not isinstance(dimension, int):
            raise TypeError("embedding dimension must be a positive integer")
        if dimension < 32:
            raise ValueError("embedding dimension must be at least 32")
        self.dimension = dimension

    def __call__(self, text: str) -> NDArray[np.float64]:
        normalized = _validate_text(text, "text", MAX_PAYLOAD_CHARS)
        tokens = _TOKEN_PATTERN.findall(normalized.casefold())
        if not tokens:
            tokens = [normalized.casefold()]

        features: list[tuple[str, float]] = [(token, 1.0) for token in tokens]
        features.extend(
            (f"{left}\0{right}", 1.35)
            for left, right in zip(tokens, tokens[1:], strict=False)
        )

        vector = np.zeros(self.dimension, dtype=np.float64)
        for feature, weight in features:
            digest = hashlib.blake2b(
                feature.encode("utf-8"),
                digest_size=16,
                person=b"echo-veil-emb-v1",
            ).digest()
            index = int.from_bytes(digest[:8], "big") % self.dimension
            sign = 1.0 if digest[8] & 1 else -1.0
            vector[index] += sign * weight

        magnitude = float(np.linalg.norm(vector))
        if not math.isfinite(magnitude) or magnitude == 0.0:
            raise ValueError("text did not produce a usable embedding")
        return vector / magnitude


class _EncryptedPayloadStore:
    """Caller-owned encrypted content store keyed by Echo Veil vine id."""

    def __init__(self, path: Path, key: bytes) -> None:
        self.path = path
        _secure_regular_file(path)
        self._cipher = AESGCM(key)
        self._dedupe_key = key
        self._connection = sqlite3.connect(
            str(path), timeout=5.0, isolation_level=None, check_same_thread=False
        )
        try:
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA secure_delete = ON")
            self._connection.execute("PRAGMA trusted_schema = OFF")
            self._connection.execute("PRAGMA synchronous = FULL")
            mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise RuntimeError("payload database WAL mode could not be enabled")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS payloads (
                    vine_id TEXT PRIMARY KEY NOT NULL,
                    topic TEXT NOT NULL,
                    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                    ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 16),
                    content_hash TEXT UNIQUE NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
        except Exception:
            self._connection.close()
            raise

    def digest(self, topic: str, payload: str) -> str:
        digest = hashlib.blake2b(
            key=self._dedupe_key,
            digest_size=32,
            person=b"echo-v-dedupe-v1",
        )
        digest.update(topic.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload.encode("utf-8"))
        return digest.hexdigest()

    def find_by_hash(self, content_hash: str) -> tuple[str, str] | None:
        row = self._connection.execute(
            "SELECT vine_id, topic FROM payloads WHERE content_hash = ?",
            (content_hash,),
        ).fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1])

    def put(self, vine_id: str, topic: str, payload: str, content_hash: str) -> None:
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, payload.encode("utf-8"), _aad(vine_id))
        self._connection.execute(
            """
            INSERT INTO payloads(
                vine_id, topic, nonce, ciphertext, content_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (vine_id, topic, nonce, ciphertext, content_hash, time.time()),
        )

    def get(self, vine_id: str) -> str | None:
        row = self._connection.execute(
            "SELECT nonce, ciphertext FROM payloads WHERE vine_id = ?", (vine_id,)
        ).fetchone()
        if row is None:
            return None
        try:
            plaintext = self._cipher.decrypt(
                bytes(row[0]), bytes(row[1]), _aad(vine_id)
            )
        except InvalidTag as exc:
            raise RuntimeError("stored payload authentication failed") from exc
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("stored payload is not valid UTF-8") from exc

    def delete(self, vine_id: str) -> bool:
        result = self._connection.execute(
            "DELETE FROM payloads WHERE vine_id = ?", (vine_id,)
        )
        return result.rowcount > 0

    def __len__(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) FROM payloads").fetchone()
        return int(row[0]) if row is not None else 0

    def close(self) -> None:
        self._connection.close()


class AgentMemory:
    """Concrete Echo Veil memory adapter for a single local host profile."""

    def __init__(
        self,
        state_dir: str | os.PathLike[str] | None = None,
        *,
        profile: str = "default",
        capacity: int = DEFAULT_CAPACITY,
        embed: Callable[[str], NDArray[np.float64]] | None = None,
    ) -> None:
        profile_name = _validate_profile(profile)
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("capacity must be a positive integer")
        if capacity <= 0:
            raise ValueError("capacity must be a positive integer")

        base = (
            default_state_dir() if state_dir is None else Path(state_dir).expanduser()
        )
        self.profile_dir = _secure_directory(base / profile_name)
        self._embed = embed or HashingTextEmbedder()
        key = _load_or_create_key(self.profile_dir / "agent.key")
        self._payloads = _EncryptedPayloadStore(self.profile_dir / "payloads.db", key)
        self._store: SQLiteStore | None = None
        try:
            self._store = SQLiteStore(self.profile_dir / "echo-veil.db")
            self.oracle = Oracle(
                WorkspaceConfig(capacity=capacity),
                shield=AesGcmCryptoShield(key),
                environment="staging",
                storage=cast(TransactionalEvictionStore, self._store),
            )
        except Exception:
            self._payloads.close()
            if self._store is not None:
                self._store.close()
            raise

    def remember(self, topic: str, payload: str) -> dict[str, Any]:
        clean_topic = _validate_text(topic, "topic", MAX_TOPIC_CHARS)
        clean_payload = _validate_text(payload, "payload", MAX_PAYLOAD_CHARS)
        content_hash = self._payloads.digest(clean_topic, clean_payload)
        existing = self._payloads.find_by_hash(content_hash)
        if existing is not None and self._managed_exists(existing[0]):
            return {
                "vine_id": existing[0],
                "topic": existing[1],
                "created": False,
                "duplicate": True,
            }
        if existing is not None:
            self._payloads.delete(existing[0])

        vector = self._embed(f"{clean_topic}\n{clean_payload}")
        vine = self.oracle.sprout(clean_topic, vector)
        try:
            self._payloads.put(vine.vine_id, clean_topic, clean_payload, content_hash)
        except sqlite3.IntegrityError:
            self.oracle.forget(vine.vine_id)
            winner = self._payloads.find_by_hash(content_hash)
            if winner is None:
                raise
            return {
                "vine_id": winner[0],
                "topic": winner[1],
                "created": False,
                "duplicate": True,
            }
        except Exception:
            self.oracle.forget(vine.vine_id)
            raise
        return {
            "vine_id": vine.vine_id,
            "topic": clean_topic,
            "created": True,
            "duplicate": False,
        }

    def recall(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float = 0.35,
        allow_inferential: bool = False,
    ) -> dict[str, Any]:
        clean_query = _validate_text(query, "query", MAX_QUERY_CHARS)
        if isinstance(top_k, bool) or not isinstance(top_k, int):
            raise TypeError("top_k must be an integer")
        if not 1 <= top_k <= MAX_RECALL_RESULTS:
            raise ValueError(f"top_k must be between 1 and {MAX_RECALL_RESULTS}")
        if isinstance(min_score, bool) or not isinstance(min_score, (int, float)):
            raise TypeError("min_score must be a finite number")
        threshold = float(min_score)
        if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise ValueError("min_score must be between 0 and 1")
        if not isinstance(allow_inferential, bool):
            raise TypeError("allow_inferential must be a bool")

        intent = self._embed(clean_query)
        lifecycle = self.oracle.observe(intent)
        candidates: dict[str, tuple[float, str, str]] = {}
        for vine in self.oracle.workspace.active():
            if vine.score >= threshold:
                candidates[vine.vine_id] = (vine.score, vine.topic, "active")

        cold_limit = min(MAX_RECALL_RESULTS * 3, max(top_k * 3, 10))
        for vine_id, score in self.oracle.search_index(intent, top_k=cold_limit):
            if score < threshold:
                continue
            metadata = self.oracle.archived_metadata(vine_id) or {}
            topic = str(metadata.get("topic", "archived memory"))
            current = candidates.get(vine_id)
            if current is None or score > current[0]:
                candidates[vine_id] = (score, topic, "archive")

        results: list[dict[str, Any]] = []
        gated_count = 0
        for vine_id, (score, topic, source) in sorted(
            candidates.items(), key=lambda item: item[1][0], reverse=True
        ):
            policy = classify(score)
            try:
                self.oracle.check_generation_gate(score, override=allow_inferential)
            except GenerationGated:
                gated_count += 1
                results.append(
                    {
                        "vine_id": vine_id,
                        "topic": topic,
                        "score": round(score, 6),
                        "source": source,
                        "confidence_band": policy.band.value,
                        "confidence_indicator": policy.indicator,
                        "gated": True,
                        "payload": None,
                    }
                )
            else:
                payload = self._payloads.get(vine_id)
                if payload is None:
                    continue
                if source == "active":
                    self.oracle.reinforce(vine_id)
                results.append(
                    {
                        "vine_id": vine_id,
                        "topic": topic,
                        "score": round(score, 6),
                        "source": source,
                        "confidence_band": policy.band.value,
                        "confidence_indicator": policy.indicator,
                        "gated": False,
                        "payload": payload,
                    }
                )
            if len(results) >= top_k:
                break

        return {
            "query": clean_query,
            "results": results,
            "gated_count": gated_count,
            "lifecycle": lifecycle,
        }

    def forget(self, vine_id: str) -> dict[str, Any]:
        clean_id = _validate_text(vine_id, "vine_id", 128)
        # Revoke content access before cleaning derived lifecycle state.
        payload_deleted = self._payloads.delete(clean_id)
        memory_deleted = self.oracle.forget(clean_id)
        return {
            "vine_id": clean_id,
            "forgotten": payload_deleted or memory_deleted,
            "payload_deleted": payload_deleted,
            "lifecycle_deleted": memory_deleted,
        }

    def doctor(self) -> dict[str, Any]:
        capability = self.oracle.capability_report().as_dict()
        key_mode = stat.S_IMODE((self.profile_dir / "agent.key").stat().st_mode)
        return {
            "adapter_ready": True,
            "mode": "local-staging",
            "profile": self.profile_dir.name,
            "payload_count": len(self._payloads),
            "active_count": len(self.oracle.workspace.vines),
            "archived_count": len(self.oracle.index),
            "key_owner_only": key_mode == 0o600,
            "capability_report": capability,
            "limitations": [
                "The bundled hashing embedder is keyword-oriented, not a semantic model.",
                "Memory capture is opt-in; neither host is silently recorded.",
                "Topics remain plaintext metadata in the local owner-only databases.",
                "AES-GCM local staging is not the production enclave profile.",
            ],
        }

    def _managed_exists(self, vine_id: str) -> bool:
        return (
            self.oracle.workspace.get(vine_id) is not None
            or self.oracle.archived_metadata(vine_id) is not None
        )

    def close(self) -> None:
        self._payloads.close()
        if self._store is not None:
            self._store.close()

    def __enter__(self) -> AgentMemory:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def default_state_dir() -> Path:
    configured = os.environ.get("ECHO_VEIL_STATE_DIR")
    if configured:
        return Path(configured).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Echo Veil"
    data_home = os.environ.get("XDG_DATA_HOME")
    if data_home:
        return Path(data_home).expanduser() / "echo-veil"
    return Path.home() / ".local" / "share" / "echo-veil"


def _validate_text(value: str, name: str, max_chars: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    result = value.strip()
    if not result:
        raise ValueError(f"{name} must be non-empty")
    if len(result) > max_chars:
        raise ValueError(f"{name} must be at most {max_chars} characters")
    return result


def _validate_profile(value: str) -> str:
    if not isinstance(value, str) or not _PROFILE_PATTERN.fullmatch(value):
        raise ValueError(
            "profile must be 1-64 letters, digits, dots, underscores, or hyphens"
        )
    if value in {".", ".."}:
        raise ValueError("profile must not be a relative path marker")
    return value


def _secure_directory(path: Path) -> Path:
    if path.exists() and path.is_symlink():
        raise ValueError("state directory must not be a symbolic link")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError("state directory must be a directory")
    if os.name != "nt":
        path.chmod(0o700)
    return path.absolute()


def _secure_regular_file(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{path.name} must be a regular file")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    key = AesGcmCryptoShield.generate_key()
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        descriptor = -1
    if descriptor >= 0:
        try:
            os.write(descriptor, key)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return key

    read_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
    descriptor = os.open(path, read_flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("agent key must be a regular file")
        stored = os.read(descriptor, 33)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    if len(stored) != 32:
        raise ValueError("agent key must contain exactly 32 bytes")
    return stored


def _aad(vine_id: str) -> bytes:
    return b"echo-veil-agent-payload-v1\0" + vine_id.encode("utf-8")
