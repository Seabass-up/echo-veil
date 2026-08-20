"""Durable, local-first host adapter for agent runtimes.

The core Echo Veil package deliberately leaves text embedding and authorized
payload storage to its host. Agent runtimes need a concrete implementation of
those responsibilities, so this module provides a small local adapter:

* an explicit local Ollama semantic embedder or offline hashing fallback;
* AES-GCM protected Echo Veil anchors;
* a separate AES-GCM encrypted payload database; and
* confidence-gated recall across active and archived memory.

It is intended for one local operating-system user.  Multi-user authorization,
remote synchronization, and production enclave guarantees remain host duties.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import re
import sqlite3
import stat
import sys
import time
import uuid
from collections import deque
from collections.abc import Callable
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, TypeVar, cast, runtime_checkable
from urllib.parse import urlsplit

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from numpy.typing import NDArray

from ._json import strict_json_loads
from .agent_security import (
    AES_GCM_NONCE_BYTES,
    KeyUnavailable,
    ProfileKeyring,
    ScopedAesGcmShield,
    ScopedProtectedBlob,
    ScopedProtectedVector,
    _binary_noninheritable_read_flags,
    opaque_topic,
    scoped_aad,
    _windows_create_private_staging,
    _windows_ensure_private_directory,
    _windows_expected_private_security,
    _windows_open_private_file,
    _windows_pinned_directory_chain,
    _windows_verify_descriptor,
    _windows_verify_private_directory,
    _windows_verify_private_sqlite_sidecars,
)
from .archive import TransactionalEvictionStore
from .confidence import classify
from .crypto_shield import AesGcmCryptoShield
from .oracle import GenerationGated, Oracle
from .persistence import SQLiteStore
from .proximity import time_decay
from .memory_layers import (
    LogicKind,
    MemoryLayer,
    MemoryLayerContract,
    migrated_short_term_contract,
    new_memory_contract,
)
from .local_readiness import (
    LEGACY_MIGRATION_MODE,
    LOCAL_PRODUCTION_MODE,
    LOCAL_STAGING_MODE,
    OFFLINE_READ_ONLY_MODE,
    LocalReadinessEvidence,
    LocalReadinessState,
    build_capabilities_v1,
    remediation_messages,
)
from .vectors import cosine_similarity
from .workspace import WorkspaceConfig

DEFAULT_EMBEDDING_DIMENSION = 384
DEFAULT_OLLAMA_EMBEDDING_DIMENSION = 1024
DEFAULT_OLLAMA_MODEL = "qwen3-embedding:latest"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_KEEP_ALIVE_SECONDS = 300
MAX_OLLAMA_KEEP_ALIVE_SECONDS = 3_600
MAX_OLLAMA_CONTEXT_LENGTH = 262_144
MAX_OLLAMA_GPU_LAYERS = 2_048
DEFAULT_SEMANTIC_MIN_SCORE = 0.44
DEFAULT_ANSWERABILITY_MIN_SCORE = 0.42
DEFAULT_AVAILABILITY_MIN_SCORE = 0.45
DEFAULT_HASHING_MIN_SCORE = 0.35
DEFAULT_CAPACITY = 400
MAX_TOPIC_CHARS = 512
MAX_PAYLOAD_CHARS = 100_000
MAX_LIVE_MEMORY_CHARS = 20_000
MAX_SHORT_TERM_MEMORY_CHARS = 12_000
MAX_LONG_TERM_MEMORY_CHARS = 2_000
MAX_CONTEXTUAL_LOGIC_MEMORY_CHARS = 4_000
MAX_AGENT_MEMORY_WRITE_CHARS = max(
    MAX_LIVE_MEMORY_CHARS,
    MAX_SHORT_TERM_MEMORY_CHARS,
    MAX_LONG_TERM_MEMORY_CHARS,
    MAX_CONTEXTUAL_LOGIC_MEMORY_CHARS,
)
MEMORY_CONTENT_POLICY = "bounded-seed-crystal-v1"
MAX_QUERY_CHARS = 20_000
MAX_RECALL_RESULTS = 20
MAX_CONTEXT_RECORDS = 20
MAX_CONTEXT_DEPTH = 2
MAX_CONTEXT_EDGES = 40
MAX_COMPETING_MEMORY_GROUPS = 4
MAX_COMPETING_MEMORY_IDS = 3
MAX_EMBEDDING_RESPONSE_BYTES = 4_194_304
DEFAULT_EMBEDDING_TIMEOUT_SECONDS = 30.0
MAX_MEMORY_PASSAGES = 12
MAX_PASSAGE_CHARS = 1_600
MAX_LEXICAL_FEATURES = 4_096
_SQLITE_BUSY_CODE = int(getattr(sqlite3, "SQLITE_BUSY", 5))
_SQLITE_LOCKED_CODE = int(getattr(sqlite3, "SQLITE_LOCKED", 6))
_SQLITE_LOCK_MESSAGES = frozenset(
    {
        "database is locked",
        "database table is locked",
        "database schema is locked",
    }
)
MAX_QUERY_FEATURES = 256
MAX_RETRIEVAL_CANDIDATES = 900
PAYLOAD_SCHEMA_VERSION = 2
LEGACY_PAYLOAD_SCHEMA_VERSION = 1
DEFAULT_PROFILE_LOCK_TIMEOUT_SECONDS = 30.0
LEXICAL_BOOST = 0.35
ANSWERABILITY_BOOST = 0.20
MIN_AVAILABILITY_FEATURES = 2
AMBIGUOUS_RANKING_MARGIN = 0.05
MMR_RELEVANCE_WEIGHT = 0.88
RETRIEVAL_SCHEMA_VERSION = "protected-hybrid-maxsim-v1"
MEMORY_CONTRACT_SCHEMA = "shielded-four-layer-v1"
MEMORY_CONTRACT_METADATA_PREFIX = "memory_contract:"
RECORD_INTEGRITY_SCHEMA = "record-integrity-hmac-v1"
RECORD_INTEGRITY_METADATA_PREFIX = "record_integrity:"
MEMORY_QUERY_INSTRUCTION = (
    "Given a memory recall query, retrieve the stored personal or operational "
    "memory that answers it"
)
ANSWERABILITY_QUERY_INSTRUCTION = (
    "Retrieve a stored memory passage only when it explicitly contains the answer "
    "to the requested attribute or predicate. Ignore subject-only similarity."
)
_PROFILE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}\Z")
_EMBEDDER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}\Z")
_QWEN3_EMBEDDING_IDENTITY = re.compile(
    r"ollama:qwen3-embedding:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}:"
    r"dimension:[1-9][0-9]*:instruction:[0-9a-f]{64}\Z"
)
_TOKEN_PATTERN = re.compile(r"[^\W_]+", re.UNICODE)
_TRANSCRIPT_ROLE_LINE = re.compile(
    r"(?im)^[ \t]{0,8}"
    r"(user|assistant|system|developer|tool|human|agent)"
    r"[ \t]*:[ \t]*\S"
)
_TRANSCRIPT_JSON_ROLE = re.compile(
    r'(?i)"role"[ \t\r\n]*:[ \t\r\n]*'
    r'"(?:user|assistant|system|developer|tool)"'
)
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "how",
        "i",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "should",
        "that",
        "the",
        "this",
        "to",
        "what",
        "when",
        "where",
        "which",
        "who",
        "with",
    }
)


@dataclass(frozen=True)
class _StoredCandidate:
    vine_id: str
    semantic_score: float | None
    answerability_score: float | None
    lexical_score: float
    best_vector: NDArray[np.float64] | None
    topic: str
    effective_at: float
    superseded_by: str | None
    superseded_at: float | None


@dataclass(frozen=True)
class _RankedCandidate:
    vine_id: str
    topic: str
    source: str
    relevance_score: float
    semantic_score: float | None
    answerability_score: float | None
    lexical_score: float
    lifecycle_score: float | None
    best_vector: NDArray[np.float64] | None
    effective_at: float
    superseded_by: str | None
    superseded_at: float | None
    temporal_current: bool


@dataclass(frozen=True, slots=True)
class _AvailabilityCandidate:
    vine_id: str
    topic: str
    score: float
    lexical_score: float
    predicate_score: float
    matched_features: int
    effective_at: float
    superseded_by: str | None
    superseded_at: float | None
    temporal_current: bool


class _CompetingCandidate(Protocol):
    """Minimum protected metadata needed to preserve a competing pair."""

    @property
    def vine_id(self) -> str: ...

    @property
    def topic(self) -> str: ...

    @property
    def temporal_current(self) -> bool: ...


_CompetingCandidateT = TypeVar(
    "_CompetingCandidateT",
    bound=_CompetingCandidate,
)


class EmbeddingUnavailable(RuntimeError):
    """The configured local embedding service or model cannot currently run."""


def _is_sqlite_lock_error(exc: sqlite3.OperationalError) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    if isinstance(code, int) and not isinstance(code, bool):
        return code & 0xFF in {_SQLITE_BUSY_CODE, _SQLITE_LOCKED_CODE}
    return str(exc).strip().casefold() in _SQLITE_LOCK_MESSAGES


class _ProfileWriterLease:
    """Serialize one profile's process-local L1 snapshot through SQLite locking."""

    def __init__(self, path: Path, timeout_seconds: float) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(
            timeout_seconds, (int, float)
        ):
            raise TypeError("profile lock timeout must be a finite positive number")
        timeout = float(timeout_seconds)
        if not math.isfinite(timeout) or not 0.0 < timeout <= 120.0:
            raise ValueError("profile lock timeout must be within (0, 120] seconds")
        _secure_regular_file(path)
        self._connection = sqlite3.connect(
            str(path),
            timeout=timeout,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            self._connection.execute(
                f"PRAGMA busy_timeout = {max(1, int(timeout * 1000))}"
            )
            self._connection.execute("PRAGMA trusted_schema = OFF")
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            self._connection.close()
            if _is_sqlite_lock_error(exc):
                raise RuntimeError(
                    "memory profile is already in use by another writer"
                ) from exc
            raise

    def close(self) -> None:
        if self._connection.in_transaction:
            self._connection.execute("ROLLBACK")
        self._connection.close()


@dataclass(frozen=True)
class _MigrationRecord:
    vine_id: str
    topic: str
    effective_at: float
    superseded_by: str | None


@runtime_checkable
class TextEmbedder(Protocol):
    """Stable document/query embedding contract used by ``AgentMemory``."""

    identity: str
    name: str
    model: str
    dimension: int
    semantic: bool
    default_min_score: float

    def embed_document(self, text: str) -> NDArray[np.float64]:
        """Embed text for durable document indexing."""
        raise NotImplementedError

    def embed_query(self, text: str) -> NDArray[np.float64]:
        """Embed text for query-time retrieval."""
        raise NotImplementedError


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
        self.name = "hashing"
        self.model = "blake2b-token-bigram-v1"
        self.identity = f"hashing:{self.model}:{dimension}"
        self.semantic = False
        self.default_min_score = DEFAULT_HASHING_MIN_SCORE

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

    def embed_document(self, text: str) -> NDArray[np.float64]:
        return self(text)

    def embed_query(self, text: str) -> NDArray[np.float64]:
        return self(text)

    def embed_documents(self, texts: list[str]) -> list[NDArray[np.float64]]:
        return [self.embed_document(text) for text in texts]


class OllamaTextEmbedder:
    """Embed documents locally with an installed, digest-pinned Ollama model.

    The transport accepts loopback IP literals only, never follows redirects,
    bounds responses, and does not silently fall back to keyword hashing.
    Qwen3 retrieval queries receive the instruction format recommended by the
    model authors while stored documents remain unprefixed.
    """

    def __init__(
        self,
        model: str = DEFAULT_OLLAMA_MODEL,
        *,
        base_url: str = DEFAULT_OLLAMA_URL,
        dimension: int = DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
        timeout_seconds: float = DEFAULT_EMBEDDING_TIMEOUT_SECONDS,
        query_instruction: str = MEMORY_QUERY_INSTRUCTION,
        keep_alive_seconds: int = DEFAULT_OLLAMA_KEEP_ALIVE_SECONDS,
        context_length: int | None = None,
        gpu_layers: int | None = None,
    ) -> None:
        if not isinstance(model, str) or not _MODEL_PATTERN.fullmatch(model):
            raise ValueError("Ollama model must be a safe non-empty model name")
        if isinstance(dimension, bool) or not isinstance(dimension, int):
            raise TypeError("embedding dimension must be a positive integer")
        if dimension < 32 or dimension > 65_536:
            raise ValueError("embedding dimension must be between 32 and 65536")
        if isinstance(timeout_seconds, bool) or not isinstance(
            timeout_seconds, (int, float)
        ):
            raise TypeError("embedding timeout must be a finite positive number")
        timeout = float(timeout_seconds)
        if not math.isfinite(timeout) or timeout <= 0.0 or timeout > 120.0:
            raise ValueError(
                "embedding timeout must be positive and at most 120 seconds"
            )
        if isinstance(keep_alive_seconds, bool) or not isinstance(
            keep_alive_seconds, int
        ):
            raise TypeError("embedding keep-alive must be an integer number of seconds")
        if not 0 <= keep_alive_seconds <= MAX_OLLAMA_KEEP_ALIVE_SECONDS:
            raise ValueError("embedding keep-alive must be between 0 and 3600 seconds")
        if context_length is not None:
            if isinstance(context_length, bool) or not isinstance(context_length, int):
                raise TypeError("embedding context length must be an integer")
            if not 512 <= context_length <= MAX_OLLAMA_CONTEXT_LENGTH:
                raise ValueError(
                    "embedding context length must be between 512 and 262144"
                )
        if gpu_layers is not None:
            if isinstance(gpu_layers, bool) or not isinstance(gpu_layers, int):
                raise TypeError("embedding GPU layers must be an integer")
            if not 0 <= gpu_layers <= MAX_OLLAMA_GPU_LAYERS:
                raise ValueError("embedding GPU layers must be between 0 and 2048")
        instruction = _validate_text(
            query_instruction,
            "query instruction",
            512,
        )

        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.hostname is None
        ):
            raise ValueError("Ollama URL must be an HTTP loopback origin")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:
            raise ValueError("Ollama URL must use a loopback IP literal") from exc
        if not address.is_loopback:
            raise ValueError("Ollama URL must use a loopback IP literal")

        try:
            port = parsed.port or 80
        except ValueError as exc:
            raise ValueError("Ollama URL contains an invalid port") from exc

        self._host = parsed.hostname
        self._port = port
        self._timeout_seconds = timeout
        self._query_instruction = instruction
        self._keep_alive = f"{keep_alive_seconds}s"
        self._runtime_options: dict[str, int] = {}
        if context_length is not None:
            self._runtime_options["num_ctx"] = context_length
        if gpu_layers is not None:
            self._runtime_options["num_gpu"] = gpu_layers
        self.name = "ollama"
        self.model = model if ":" in model else f"{model}:latest"
        self.dimension = dimension
        self.semantic = True
        self.default_min_score = DEFAULT_SEMANTIC_MIN_SCORE
        digest, maximum_dimension = self._resolve_model()
        if dimension > maximum_dimension:
            raise ValueError(
                f"requested embedding dimension {dimension} exceeds model maximum "
                f"{maximum_dimension}"
            )
        instruction_digest = hashlib.sha256(instruction.encode("utf-8")).hexdigest()
        self._model_digest = digest
        self._maximum_dimension = maximum_dimension
        self.identity = (
            f"ollama:{self.model}@sha256:{digest}:dimension:{dimension}:"
            f"instruction:{instruction_digest}"
        )

    def embed_document(self, text: str) -> NDArray[np.float64]:
        return self._embed(_validate_text(text, "text", MAX_PAYLOAD_CHARS))

    def embed_documents(self, texts: list[str]) -> list[NDArray[np.float64]]:
        if not isinstance(texts, list) or not texts:
            raise ValueError("embedding document batch must be a non-empty list")
        if len(texts) > MAX_MEMORY_PASSAGES:
            raise ValueError(
                f"embedding document batch must contain at most {MAX_MEMORY_PASSAGES} items"
            )
        clean = [_validate_text(text, "text", MAX_PAYLOAD_CHARS) for text in texts]
        return self._embed_batch(clean)

    def embed_query(self, text: str) -> NDArray[np.float64]:
        clean = _validate_text(text, "query", MAX_QUERY_CHARS)
        instructed = f"Instruct: {self._query_instruction}\nQuery: {clean}"
        return self._embed(instructed)

    def embed_retrieval_queries(
        self, text: str
    ) -> tuple[NDArray[np.float64], NDArray[np.float64]]:
        """Batch broad-recall and predicate-focused queries in one local request."""
        clean = _validate_text(text, "query", MAX_QUERY_CHARS)
        predicate_query = _predicate_query(clean)
        broad = f"Instruct: {self._query_instruction}\nQuery: {clean}"
        answerability = (
            f"Instruct: {ANSWERABILITY_QUERY_INSTRUCTION}\nQuery: {predicate_query}"
        )
        broad_vector, answerability_vector = self._embed_batch([broad, answerability])
        return broad_vector, answerability_vector

    def embed_answerability_query(self, text: str) -> NDArray[np.float64]:
        """Embed the requested predicate without letting subject identity dominate."""
        clean = _validate_text(text, "query", MAX_QUERY_CHARS)
        predicate_query = _predicate_query(clean)
        instructed = (
            f"Instruct: {ANSWERABILITY_QUERY_INSTRUCTION}\nQuery: {predicate_query}"
        )
        return self._embed(instructed)

    def __call__(self, text: str) -> NDArray[np.float64]:
        return self.embed_document(text)

    def _embed(self, text: str) -> NDArray[np.float64]:
        return self._embed_batch([text])[0]

    def _embed_batch(self, texts: list[str]) -> list[NDArray[np.float64]]:
        self._assert_model_identity()
        request: dict[str, object] = {
            "model": self.model,
            "input": texts,
            "dimensions": self.dimension,
            "truncate": False,
            "keep_alive": self._keep_alive,
        }
        if self._runtime_options:
            request["options"] = dict(self._runtime_options)
        response = self._request_json("POST", "/api/embed", request)
        embeddings = response.get("embeddings")
        if not isinstance(embeddings, list) or len(embeddings) != len(texts):
            raise RuntimeError("local Ollama returned an invalid embedding response")
        vectors: list[NDArray[np.float64]] = []
        for item in embeddings:
            try:
                if (
                    not isinstance(item, list)
                    or len(item) != self.dimension
                    or any(
                        isinstance(part, bool) or not isinstance(part, (int, float))
                        for part in item
                    )
                ):
                    raise ValueError
                vector = np.asarray(item, dtype=np.float64)
                vectors.append(
                    _normalize_embedding_vector(
                        vector,
                        expected_dimension=self.dimension,
                        source="local Ollama",
                    )
                )
            except (TypeError, ValueError) as exc:
                raise RuntimeError(
                    "local Ollama returned an invalid embedding vector"
                ) from exc
        return vectors

    def _assert_model_identity(self) -> None:
        digest, maximum_dimension = self._resolve_model()
        if digest != self._model_digest or maximum_dimension != self._maximum_dimension:
            raise RuntimeError(
                "local Ollama model identity changed after adapter initialization"
            )

    def _resolve_model(self) -> tuple[str, int]:
        response = self._request_json("GET", "/api/tags")
        models = response.get("models")
        if not isinstance(models, list):
            raise RuntimeError("local Ollama returned an invalid model inventory")
        matches: list[tuple[str, int]] = []
        for entry in models:
            if not isinstance(entry, Mapping):
                continue
            if self.model not in {entry.get("name"), entry.get("model")}:
                continue
            digest = entry.get("digest")
            details = entry.get("details")
            maximum_dimension = (
                details.get("embedding_length")
                if isinstance(details, Mapping)
                else None
            )
            if (
                not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or isinstance(maximum_dimension, bool)
                or not isinstance(maximum_dimension, int)
                or maximum_dimension <= 0
            ):
                raise RuntimeError("local Ollama model metadata is incomplete")
            matches.append((digest, maximum_dimension))
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise RuntimeError("local Ollama model inventory is ambiguous")
        raise EmbeddingUnavailable(
            f"required local Ollama model is not installed: {self.model}"
        )

    def _request_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, object] | None = None,
    ) -> dict[str, Any]:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(
                dict(payload),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection(
            self._host,
            self._port,
            timeout=self._timeout_seconds,
        )
        status: int | None = None
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            status = response.status
            if status == 200:
                content_type = response.getheader("Content-Type", "") or ""
                if content_type.split(";", 1)[0].strip().lower() != "application/json":
                    raise RuntimeError("local Ollama returned an invalid content type")
                declared_length = response.getheader("Content-Length")
                if declared_length is not None and (
                    not declared_length.isascii()
                    or not declared_length.isdigit()
                    or int(declared_length) > MAX_EMBEDDING_RESPONSE_BYTES
                ):
                    raise RuntimeError("local Ollama returned an invalid response size")
            encoded = response.read(MAX_EMBEDDING_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise EmbeddingUnavailable(
                "local Ollama embedding service is unavailable"
            ) from exc
        finally:
            connection.close()
        if status != 200:
            error_type = (
                EmbeddingUnavailable if status in {502, 503, 504} else RuntimeError
            )
            raise error_type(
                f"local Ollama embedding request failed with HTTP {status}"
            )
        if len(encoded) > MAX_EMBEDDING_RESPONSE_BYTES:
            raise RuntimeError("local Ollama embedding response exceeded size limit")
        try:
            decoded = strict_json_loads(encoded)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
        ) as exc:
            raise RuntimeError("local Ollama returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("local Ollama returned an invalid JSON object")
        return decoded


class _CallableTextEmbedder:
    """Compatibility wrapper for reviewed caller-provided embedding functions."""

    def __init__(
        self,
        embed: Callable[[str], NDArray[np.float64]],
        embedder_id: str,
    ) -> None:
        if not isinstance(embedder_id, str) or not _EMBEDDER_ID_PATTERN.fullmatch(
            embedder_id
        ):
            raise ValueError("embedder_id must be a stable safe identifier")
        identifier = embedder_id
        probe = _normalize_embedding_vector(embed("echo veil dimension probe"))
        self._embed = embed
        self.dimension = int(probe.shape[0])
        self.name = "custom"
        self.model = identifier
        self.identity = f"custom:{identifier}:dimension:{self.dimension}"
        self.semantic = False
        self.default_min_score = DEFAULT_HASHING_MIN_SCORE

    def embed_document(self, text: str) -> NDArray[np.float64]:
        clean = _validate_text(text, "text", MAX_PAYLOAD_CHARS)
        return _normalize_embedding_vector(
            self._embed(clean), expected_dimension=self.dimension
        )

    def embed_query(self, text: str) -> NDArray[np.float64]:
        clean = _validate_text(text, "query", MAX_QUERY_CHARS)
        return _normalize_embedding_vector(
            self._embed(clean), expected_dimension=self.dimension
        )


class _LegacyEncryptedPayloadStore:
    """Caller-owned encrypted content store keyed by Echo Veil vine id."""

    def __init__(self, path: Path, key: bytes, *, read_only: bool = False) -> None:
        self.path = path
        self._read_only = read_only
        if read_only:
            _require_secure_regular_file(path, "payload database")
            database = f"{path.resolve().as_uri()}?mode=ro"
        else:
            _secure_regular_file(path)
            database = str(path)
        self._cipher = AESGCM(key)
        self._dedupe_key = key
        self._connection = sqlite3.connect(
            database,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
            uri=read_only,
        )
        try:
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA trusted_schema = OFF")
            version_row = self._connection.execute("PRAGMA user_version").fetchone()
            version = 0 if version_row is None else int(version_row[0])
            if version not in {0, LEGACY_PAYLOAD_SCHEMA_VERSION}:
                raise RuntimeError("unsupported payload database schema version")
            if read_only:
                self._connection.execute("PRAGMA query_only = ON")
                self._validate_existing_schema()
                self._verify_integrity()
                return
            self._connection.execute("PRAGMA secure_delete = ON")
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
            self._ensure_payload_column("effective_at", "REAL")
            self._ensure_payload_column("superseded_by", "TEXT")
            self._ensure_payload_column("superseded_at", "REAL")
            self._connection.execute(
                "UPDATE payloads SET effective_at = created_at WHERE effective_at IS NULL"
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS adapter_metadata (
                    key TEXT PRIMARY KEY NOT NULL CHECK(length(key) BETWEEN 1 AND 64),
                    value TEXT NOT NULL CHECK(length(value) BETWEEN 1 AND 2048)
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_vectors (
                    vine_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                    ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 16),
                    dimension INTEGER NOT NULL CHECK(dimension > 0),
                    PRIMARY KEY(vine_id, ordinal)
                ) WITHOUT ROWID
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_terms (
                    vine_id TEXT NOT NULL,
                    term_hash BLOB NOT NULL CHECK(length(term_hash) = 16),
                    term_count INTEGER NOT NULL CHECK(term_count > 0),
                    PRIMARY KEY(vine_id, term_hash)
                ) WITHOUT ROWID
                """
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_terms_hash "
                "ON memory_terms(term_hash)"
            )
            self._validate_existing_schema()
            self._verify_integrity()
            self._connection.execute(
                f"PRAGMA user_version = {LEGACY_PAYLOAD_SCHEMA_VERSION}"
            )
        except Exception:
            self._connection.close()
            raise

    def _validate_existing_schema(self) -> None:
        expected = {
            "payloads": (
                ("vine_id", "TEXT", 1, 1),
                ("topic", "TEXT", 1, 0),
                ("nonce", "BLOB", 1, 0),
                ("ciphertext", "BLOB", 1, 0),
                ("content_hash", "TEXT", 1, 0),
                ("created_at", "REAL", 1, 0),
                ("effective_at", "REAL", 0, 0),
                ("superseded_by", "TEXT", 0, 0),
                ("superseded_at", "REAL", 0, 0),
            ),
            "adapter_metadata": (
                ("key", "TEXT", 1, 1),
                ("value", "TEXT", 1, 0),
            ),
            "memory_vectors": (
                ("vine_id", "TEXT", 1, 1),
                ("ordinal", "INTEGER", 1, 2),
                ("nonce", "BLOB", 1, 0),
                ("ciphertext", "BLOB", 1, 0),
                ("dimension", "INTEGER", 1, 0),
            ),
            "memory_terms": (
                ("vine_id", "TEXT", 1, 1),
                ("term_hash", "BLOB", 1, 2),
                ("term_count", "INTEGER", 1, 0),
            ),
        }
        for table, expected_columns in expected.items():
            rows = self._connection.execute(f"PRAGMA table_xinfo({table})").fetchall()
            actual = tuple(
                (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
                for row in rows
                if int(row[6]) == 0
            )
            if actual != expected_columns:
                raise RuntimeError("payload database schema validation failed")
        objects = {
            (str(row[0]), str(row[1]), str(row[2]))
            for row in self._connection.execute(
                "SELECT type, name, tbl_name FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        expected_objects = {
            *(("table", table, table) for table in expected),
            ("index", "idx_memory_terms_hash", "memory_terms"),
        }
        if objects != expected_objects:
            raise RuntimeError("payload database schema validation failed")
        index_columns = tuple(
            str(row[2])
            for row in self._connection.execute(
                "PRAGMA index_info(idx_memory_terms_hash)"
            )
        )
        if index_columns != ("term_hash",):
            raise RuntimeError("payload database schema validation failed")

    def _verify_integrity(self) -> None:
        rows = self._connection.execute("PRAGMA quick_check").fetchall()
        if tuple(str(row[0]) for row in rows) != ("ok",):
            raise RuntimeError("payload database integrity check failed")
        foreign_key_rows = self._connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        if foreign_key_rows:
            raise RuntimeError("payload database foreign-key integrity check failed")
        orphan_queries = (
            "SELECT 1 FROM memory_vectors AS child "
            "LEFT JOIN payloads ON payloads.vine_id = child.vine_id "
            "WHERE payloads.vine_id IS NULL LIMIT 1",
            "SELECT 1 FROM memory_terms AS child "
            "LEFT JOIN payloads ON payloads.vine_id = child.vine_id "
            "WHERE payloads.vine_id IS NULL LIMIT 1",
        )
        for query in orphan_queries:
            orphan = self._connection.execute(query).fetchone()
            if orphan is not None:
                raise RuntimeError(
                    "payload database foreign-key integrity check failed"
                )

    def _ensure_payload_column(self, name: str, declaration: str) -> None:
        columns = {
            str(row[1])
            for row in self._connection.execute("PRAGMA table_info(payloads)")
        }
        if name not in columns:
            self._connection.execute(
                f"ALTER TABLE payloads ADD COLUMN {name} {declaration}"
            )

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
        return str(row[0]), _validate_stored_topic(row[1])

    def put(
        self,
        vine_id: str,
        topic: str,
        payload: str,
        content_hash: str,
        *,
        vectors: list[NDArray[np.float64]],
        effective_at: float,
        supersedes: tuple[str, ...],
        contract: MemoryLayerContract | None = None,
    ) -> None:
        if contract is not None:
            raise RuntimeError(
                "legacy profiles are migration-only because their layer metadata "
                "cannot satisfy the scoped shield contract"
            )
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, payload.encode("utf-8"), _aad(vine_id))
        created_at = time.time()
        terms = self._term_features(f"{topic}\n{payload}", MAX_LEXICAL_FEATURES)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            for prior_id in supersedes:
                row = self._connection.execute(
                    "SELECT effective_at, superseded_by FROM payloads WHERE vine_id = ?",
                    (prior_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"superseded memory does not exist: {prior_id}")
                if row[1] is not None:
                    raise ValueError(f"memory is already superseded: {prior_id}")
                if row[0] is not None and float(row[0]) > effective_at:
                    raise ValueError(
                        "replacement effective_at must not precede superseded memory"
                    )
            self._connection.execute(
                """
                INSERT INTO payloads(
                    vine_id, topic, nonce, ciphertext, content_hash, created_at,
                    effective_at, superseded_by, superseded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    vine_id,
                    topic,
                    nonce,
                    ciphertext,
                    content_hash,
                    created_at,
                    effective_at,
                ),
            )
            for ordinal, vector in enumerate(vectors):
                clean = _normalize_embedding_vector(vector)
                vector_nonce = os.urandom(12)
                vector_ciphertext = self._cipher.encrypt(
                    vector_nonce,
                    clean.astype(np.float64, copy=False).tobytes(order="C"),
                    _vector_aad(vine_id, ordinal),
                )
                self._connection.execute(
                    """
                    INSERT INTO memory_vectors(
                        vine_id, ordinal, nonce, ciphertext, dimension
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        vine_id,
                        ordinal,
                        vector_nonce,
                        vector_ciphertext,
                        clean.size,
                    ),
                )
            self._connection.executemany(
                """
                INSERT INTO memory_terms(vine_id, term_hash, term_count)
                VALUES (?, ?, ?)
                """,
                [(vine_id, term_hash, count) for term_hash, count in terms.items()],
            )
            for prior_id in supersedes:
                self._connection.execute(
                    """
                    UPDATE payloads
                    SET superseded_by = ?, superseded_at = ?
                    WHERE vine_id = ? AND superseded_by IS NULL
                    """,
                    (vine_id, effective_at, prior_id),
                )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def get(self, vine_id: str) -> str | None:
        row = self._connection.execute(
            "SELECT nonce, ciphertext FROM payloads WHERE vine_id = ?", (vine_id,)
        ).fetchone()
        if row is None:
            return None
        nonce = bytes(row[0])
        ciphertext = bytes(row[1])
        if len(nonce) != 12 or not 16 < len(ciphertext) <= MAX_PAYLOAD_CHARS * 4 + 16:
            raise RuntimeError("stored payload has an invalid encrypted size")
        try:
            plaintext = self._cipher.decrypt(nonce, ciphertext, _aad(vine_id))
        except InvalidTag as exc:
            raise RuntimeError("stored payload authentication failed") from exc
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("stored payload is not valid UTF-8") from exc

    def delete(self, vine_id: str) -> bool:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            link = self._connection.execute(
                "SELECT superseded_by, superseded_at FROM payloads WHERE vine_id = ?",
                (vine_id,),
            ).fetchone()
            if link is None:
                self._connection.execute("ROLLBACK")
                return False
            self._connection.execute(
                "DELETE FROM memory_vectors WHERE vine_id = ?", (vine_id,)
            )
            self._connection.execute(
                "DELETE FROM memory_terms WHERE vine_id = ?", (vine_id,)
            )
            self._connection.execute(
                "DELETE FROM adapter_metadata WHERE key = ?",
                (_memory_contract_key(vine_id),),
            )
            self._connection.execute(
                """
                UPDATE payloads
                SET superseded_by = ?, superseded_at = ?
                WHERE superseded_by = ?
                """,
                (link[0], link[1], vine_id),
            )
            result = self._connection.execute(
                "DELETE FROM payloads WHERE vine_id = ?", (vine_id,)
            )
            self._connection.execute("COMMIT")
            return result.rowcount > 0
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def retrieval_candidates(
        self,
        intent: NDArray[np.float64],
        query: str,
        semantic_candidate_ids: list[str],
        answerability_intent: NDArray[np.float64] | None = None,
    ) -> dict[str, _StoredCandidate]:
        query_vector = _normalize_embedding_vector(intent)
        answerability_vector = (
            None
            if answerability_intent is None
            else _normalize_embedding_vector(
                answerability_intent,
                expected_dimension=query_vector.size,
                source="answerability embedder",
            )
        )
        lexical = self._lexical_scores(query)
        ordered_ids = list(dict.fromkeys(semantic_candidate_ids))[
            :MAX_RETRIEVAL_CANDIDATES
        ]
        candidate_ids = set(ordered_ids)
        lexical_ranked = sorted(
            lexical,
            key=lambda vine_id: (lexical[vine_id], vine_id),
            reverse=True,
        )
        for vine_id in lexical_ranked:
            if len(candidate_ids) >= MAX_RETRIEVAL_CANDIDATES:
                break
            candidate_ids.add(vine_id)
        if not candidate_ids:
            return {}
        placeholders = ",".join("?" for _ in candidate_ids)
        parameters = tuple(sorted(candidate_ids))
        semantic: dict[str, tuple[float, NDArray[np.float64]]] = {}
        answerability: dict[str, float] = {}
        # Only a bounded count of qmark placeholders is interpolated. Candidate
        # values remain SQLite parameters and never become SQL text.
        vector_query = (
            "SELECT vine_id, ordinal, nonce, ciphertext, dimension "
            "FROM memory_vectors "
            f"WHERE vine_id IN ({placeholders}) "
            "ORDER BY vine_id, ordinal"
        )
        cursor = self._connection.execute(vector_query, parameters)
        for row in cursor:
            vine_id = str(row[0])
            ordinal = int(row[1])
            dimension = int(row[4])
            if (
                ordinal < 0
                or ordinal >= MAX_MEMORY_PASSAGES
                or dimension <= 0
                or dimension > 65_536
                or dimension != query_vector.size
            ):
                raise RuntimeError("stored retrieval vector dimension mismatch")
            nonce = bytes(row[2])
            ciphertext = bytes(row[3])
            if len(nonce) != 12 or len(ciphertext) != dimension * 8 + 16:
                raise RuntimeError("stored retrieval vector has invalid encrypted size")
            try:
                raw = self._cipher.decrypt(
                    nonce,
                    ciphertext,
                    _vector_aad(vine_id, ordinal),
                )
            except InvalidTag as exc:
                raise RuntimeError(
                    "stored retrieval vector authentication failed"
                ) from exc
            expected_bytes = dimension * np.dtype(np.float64).itemsize
            if len(raw) != expected_bytes:
                raise RuntimeError("stored retrieval vector has invalid length")
            vector = np.frombuffer(raw, dtype=np.float64).copy()
            vector = _normalize_embedding_vector(
                vector,
                expected_dimension=dimension,
                source="stored retrieval vector",
            )
            score = cosine_similarity(query_vector, vector)
            current = semantic.get(vine_id)
            if current is None or score > current[0]:
                semantic[vine_id] = (score, vector)
            if answerability_vector is not None:
                answerability_score = cosine_similarity(answerability_vector, vector)
                current_answerability = answerability.get(vine_id)
                if (
                    current_answerability is None
                    or answerability_score > current_answerability
                ):
                    answerability[vine_id] = answerability_score

        payload_query = (
            "SELECT vine_id, topic, effective_at, superseded_by, superseded_at "
            "FROM payloads "
            f"WHERE vine_id IN ({placeholders})"
        )
        rows = self._connection.execute(payload_query, parameters).fetchall()
        candidates: dict[str, _StoredCandidate] = {}
        for row in rows:
            vine_id = str(row[0])
            semantic_entry = semantic.get(vine_id)
            topic = _validate_stored_topic(row[1])
            effective_at = _validate_stored_timestamp(row[2], "effective_at")
            superseded_at = (
                None
                if row[4] is None
                else _validate_stored_timestamp(row[4], "superseded_at")
            )
            candidates[vine_id] = _StoredCandidate(
                vine_id=vine_id,
                semantic_score=None if semantic_entry is None else semantic_entry[0],
                answerability_score=answerability.get(vine_id),
                lexical_score=lexical.get(vine_id, 0.0),
                best_vector=None if semantic_entry is None else semantic_entry[1],
                topic=topic,
                effective_at=effective_at,
                superseded_by=None if row[3] is None else str(row[3]),
                superseded_at=superseded_at,
            )
        return candidates

    def retrieval_index_counts(self) -> tuple[int, int]:
        indexed_row = self._connection.execute(
            "SELECT COUNT(DISTINCT vine_id) FROM memory_vectors"
        ).fetchone()
        total = len(self)
        indexed = 0 if indexed_row is None else int(indexed_row[0])
        return indexed, max(0, total - indexed)

    def record_ids_for_reindex(self) -> list[str]:
        rows = self._connection.execute(
            "SELECT vine_id FROM payloads ORDER BY created_at, vine_id"
        ).fetchall()
        return [str(row[0]) for row in rows]

    def record_for_reindex(self, vine_id: str) -> tuple[str, str]:
        row = self._connection.execute(
            "SELECT topic FROM payloads WHERE vine_id = ?", (vine_id,)
        ).fetchone()
        payload = self.get(vine_id)
        if row is None or payload is None:
            raise RuntimeError("payload disappeared during retrieval reindex")
        return _validate_stored_topic(row[0]), payload

    def records_for_migration(self) -> list[_MigrationRecord]:
        rows = self._connection.execute(
            """
            SELECT vine_id, topic, effective_at, superseded_by
            FROM payloads
            ORDER BY created_at, vine_id
            """
        ).fetchall()
        records: list[_MigrationRecord] = []
        for row in rows:
            vine_id = str(row[0])
            records.append(
                _MigrationRecord(
                    vine_id=vine_id,
                    topic=_validate_stored_topic(row[1]),
                    effective_at=_validate_stored_timestamp(row[2], "effective_at"),
                    superseded_by=None if row[3] is None else str(row[3]),
                )
            )
        return records

    def replace_retrieval_index(
        self,
        vine_id: str,
        text: str,
        vectors: list[NDArray[np.float64]],
    ) -> None:
        terms = self._term_features(text, MAX_LEXICAL_FEATURES)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            exists = self._connection.execute(
                "SELECT 1 FROM payloads WHERE vine_id = ?", (vine_id,)
            ).fetchone()
            if exists is None:
                raise RuntimeError("payload disappeared during retrieval reindex")
            self._connection.execute(
                "DELETE FROM memory_vectors WHERE vine_id = ?", (vine_id,)
            )
            self._connection.execute(
                "DELETE FROM memory_terms WHERE vine_id = ?", (vine_id,)
            )
            for ordinal, vector in enumerate(vectors):
                clean = _normalize_embedding_vector(vector)
                nonce = os.urandom(12)
                ciphertext = self._cipher.encrypt(
                    nonce,
                    clean.astype(np.float64, copy=False).tobytes(order="C"),
                    _vector_aad(vine_id, ordinal),
                )
                self._connection.execute(
                    """
                    INSERT INTO memory_vectors(
                        vine_id, ordinal, nonce, ciphertext, dimension
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (vine_id, ordinal, nonce, ciphertext, clean.size),
                )
            self._connection.executemany(
                """
                INSERT INTO memory_terms(vine_id, term_hash, term_count)
                VALUES (?, ?, ?)
                """,
                [(vine_id, term_hash, count) for term_hash, count in terms.items()],
            )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def _term_features(self, text: str, limit: int) -> dict[bytes, int]:
        raw = _lexical_features(text, limit)
        return {
            hashlib.blake2b(
                feature.encode("utf-8"),
                key=self._dedupe_key,
                digest_size=16,
                person=b"echo-v-term-v1",
            ).digest(): count
            for feature, count in raw.items()
        }

    def _lexical_matches(self, query: str) -> dict[str, tuple[float, int]]:
        query_terms = self._term_features(query, MAX_QUERY_FEATURES)
        if not query_terms:
            return {}
        placeholders = ",".join("?" for _ in query_terms)
        # Term hashes remain parameters; the generated SQL fragment contains
        # only one qmark for each bounded query feature.
        term_query = (
            "SELECT vine_id, term_hash, term_count FROM memory_terms "
            f"WHERE term_hash IN ({placeholders})"
        )
        rows = self._connection.execute(term_query, tuple(query_terms)).fetchall()
        matched_counts: dict[str, int] = {}
        matched_unique: dict[str, int] = {}
        for vine_id_raw, term_hash_raw, count_raw in rows:
            vine_id = str(vine_id_raw)
            term_hash = bytes(term_hash_raw)
            matched_counts[vine_id] = matched_counts.get(vine_id, 0) + min(
                query_terms[term_hash], int(count_raw)
            )
            matched_unique[vine_id] = matched_unique.get(vine_id, 0) + 1
        query_count = sum(query_terms.values())
        query_unique = len(query_terms)
        return {
            vine_id: (
                min(
                    1.0,
                    0.7 * (matched_counts[vine_id] / query_count)
                    + 0.3 * (matched_unique[vine_id] / query_unique),
                ),
                matched_unique[vine_id],
            )
            for vine_id in matched_counts
        }

    def _lexical_scores(self, query: str) -> dict[str, float]:
        return {
            vine_id: score
            for vine_id, (score, _matched) in self._lexical_matches(query).items()
        }

    def availability_candidates(
        self,
        query: str,
        *,
        as_of: float | None,
    ) -> list[_AvailabilityCandidate]:
        broad = self._lexical_matches(query)
        predicate = self._lexical_matches(_predicate_query(query))
        if not predicate:
            return []
        candidate_ids = sorted(
            predicate,
            key=lambda vine_id: (
                predicate[vine_id][0],
                predicate[vine_id][1],
                vine_id,
            ),
            reverse=True,
        )[:MAX_RETRIEVAL_CANDIDATES]
        placeholders = ",".join("?" for _ in candidate_ids)
        candidate_query = (
            "SELECT vine_id, topic, effective_at, superseded_by, superseded_at "
            "FROM payloads "
            f"WHERE vine_id IN ({placeholders})"
        )
        rows = self._connection.execute(
            candidate_query,
            tuple(candidate_ids),
        ).fetchall()
        candidates: list[_AvailabilityCandidate] = []
        for row in rows:
            vine_id = str(row[0])
            effective_at = _validate_stored_timestamp(row[2], "effective_at")
            superseded_at = (
                None
                if row[4] is None
                else _validate_stored_timestamp(row[4], "superseded_at")
            )
            if as_of is not None and effective_at > as_of:
                continue
            temporal_current = row[3] is None
            if as_of is not None:
                temporal_current = superseded_at is None or as_of < superseded_at
                if not temporal_current:
                    continue
            predicate_score, matched_features = predicate[vine_id]
            lexical_score = broad.get(vine_id, (0.0, 0))[0]
            score = min(1.0, 0.85 * predicate_score + 0.15 * lexical_score)
            candidates.append(
                _AvailabilityCandidate(
                    vine_id=vine_id,
                    topic=_validate_stored_topic(row[1]),
                    score=score,
                    lexical_score=lexical_score,
                    predicate_score=predicate_score,
                    matched_features=matched_features,
                    effective_at=effective_at,
                    superseded_by=None if row[3] is None else str(row[3]),
                    superseded_at=superseded_at,
                    temporal_current=temporal_current,
                )
            )
        return sorted(
            candidates,
            key=lambda item: (
                1 if item.temporal_current else 0,
                item.score,
                item.effective_at,
                item.vine_id,
            ),
            reverse=True,
        )

    def __len__(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) FROM payloads").fetchone()
        return int(row[0]) if row is not None else 0

    def get_metadata(self, key: str) -> str | None:
        row = self._connection.execute(
            "SELECT value FROM adapter_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        return None if row is None else str(row[0])

    def set_metadata(self, key: str, value: str) -> None:
        self._connection.execute(
            "INSERT OR IGNORE INTO adapter_metadata(key, value) VALUES (?, ?)",
            (key, value),
        )

    def initialize_memory_contracts(self) -> int:
        """Legacy profiles cannot claim the shielded four-layer contract."""

        return 0

    def initialize_record_integrity(self) -> int:
        """Legacy profiles cannot claim authenticated record metadata."""

        return 0

    def get_memory_contract(self, vine_id: str) -> MemoryLayerContract:
        del vine_id
        raise RuntimeError(
            "legacy profiles are migration-only; layer metadata is not fully shielded"
        )

    def set_memory_contract(
        self,
        vine_id: str,
        contract: MemoryLayerContract,
    ) -> None:
        del vine_id, contract
        raise RuntimeError(
            "legacy profiles are migration-only; layer metadata is not fully shielded"
        )

    def memory_contract_counts(self) -> dict[str, int]:
        return {layer.value: 0 for layer in MemoryLayer}

    def close(self) -> None:
        self._connection.close()


class QuarantinedRecordError(RuntimeError):
    """A record failed authentication and was isolated from retrieval."""


class _EncryptedPayloadStore(_LegacyEncryptedPayloadStore):
    """Versioned encrypted payload and protected retrieval store.

    Version 1 is retained as a read/write compatibility mode so an existing
    profile can be explicitly migrated.  Newly created profiles use version 2,
    where topics are opaque, payloads and vectors are record/scope/key bound,
    writes carry a crash-recoverable operation state, deletions are
    authenticated, and corrupt records are quarantined.
    """

    def __init__(
        self,
        path: Path,
        *,
        keyring: ProfileKeyring | None = None,
        legacy_key: bytes | None = None,
        read_only: bool = False,
    ) -> None:
        existing_version = _payload_database_version(path)
        if existing_version == LEGACY_PAYLOAD_SCHEMA_VERSION:
            if legacy_key is None:
                raise KeyUnavailable("legacy profile key is unavailable")
            self._secure_schema = False
            self._keyring = None
            self._contract_shield: ScopedAesGcmShield | None = None
            super().__init__(path, legacy_key, read_only=read_only)
            return
        if existing_version not in {0, PAYLOAD_SCHEMA_VERSION}:
            raise RuntimeError("unsupported payload database schema version")
        if keyring is None:
            raise KeyUnavailable("secure profile keyring is unavailable")

        self._secure_schema = True
        self._keyring = keyring
        self._contract_shield = ScopedAesGcmShield(keyring)
        self.path = path
        self._read_only = read_only
        if read_only:
            _require_secure_regular_file(path, "payload database")
            database = f"{path.resolve().as_uri()}?mode=ro"
        else:
            _secure_regular_file(path)
            database = str(path)
        self._connection = sqlite3.connect(
            database,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
            uri=read_only,
        )
        try:
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA trusted_schema = OFF")
            version_row = self._connection.execute("PRAGMA user_version").fetchone()
            version = 0 if version_row is None else int(version_row[0])
            if version not in {0, PAYLOAD_SCHEMA_VERSION}:
                raise RuntimeError("unsupported payload database schema version")
            if read_only:
                if version != PAYLOAD_SCHEMA_VERSION:
                    raise RuntimeError("secure payload database is not initialized")
                self._connection.execute("PRAGMA query_only = ON")
                self._validate_existing_schema()
                self._verify_integrity()
                return
            self._connection.execute("PRAGMA secure_delete = ON")
            self._connection.execute("PRAGMA synchronous = FULL")
            mode = self._connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).lower() != "wal":
                raise RuntimeError("payload database WAL mode could not be enabled")
            self._initialize_secure_schema()
            self._validate_existing_schema()
            self._verify_integrity()
            self._connection.execute(f"PRAGMA user_version = {PAYLOAD_SCHEMA_VERSION}")
        except Exception:
            self._connection.close()
            raise

    @property
    def security_schema(self) -> str:
        return "scoped-v2" if self._secure_schema else "legacy-v1"

    @property
    def metadata_protected(self) -> bool:
        return self._secure_schema

    def _initialize_secure_schema(self) -> None:
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS payloads (
                vine_id TEXT PRIMARY KEY NOT NULL,
                topic TEXT NOT NULL,
                nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 16),
                key_id TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                format_version INTEGER NOT NULL CHECK(format_version = 2),
                content_hash TEXT UNIQUE NOT NULL,
                created_at REAL NOT NULL,
                effective_at REAL NOT NULL,
                superseded_by TEXT,
                superseded_at REAL,
                operation_state TEXT NOT NULL CHECK(
                    operation_state IN ('pending', 'committed')
                )
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS adapter_metadata (
                key TEXT PRIMARY KEY NOT NULL CHECK(length(key) BETWEEN 1 AND 64),
                value TEXT NOT NULL CHECK(length(value) BETWEEN 1 AND 2048)
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_vectors (
                vine_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                nonce BLOB NOT NULL CHECK(length(nonce) = 12),
                ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 16),
                dimension INTEGER NOT NULL CHECK(dimension > 0),
                key_id TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                format_version INTEGER NOT NULL CHECK(format_version = 2),
                PRIMARY KEY(vine_id, ordinal)
            ) WITHOUT ROWID
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_terms (
                vine_id TEXT NOT NULL,
                term_hash BLOB NOT NULL CHECK(length(term_hash) = 16),
                term_count INTEGER NOT NULL CHECK(term_count > 0),
                key_id TEXT NOT NULL,
                PRIMARY KEY(vine_id, term_hash)
            ) WITHOUT ROWID
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS quarantine (
                vine_id TEXT PRIMARY KEY NOT NULL,
                reason_code TEXT NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 64),
                detected_at REAL NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS deletion_tombstones (
                vine_id TEXT PRIMARY KEY NOT NULL,
                deleted_at REAL NOT NULL,
                key_id TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                auth_tag BLOB NOT NULL CHECK(length(auth_tag) = 32)
            )
            """
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_memory_terms_hash "
            "ON memory_terms(term_hash)"
        )
        self._connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_payload_nonce "
            "ON payloads(key_id, nonce)"
        )
        self._connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_vector_nonce "
            "ON memory_vectors(key_id, nonce)"
        )

    def _validate_existing_schema(self) -> None:
        if not self._secure_schema:
            return super()._validate_existing_schema()
        expected = {
            "payloads": (
                ("vine_id", "TEXT", 1, 1),
                ("topic", "TEXT", 1, 0),
                ("nonce", "BLOB", 1, 0),
                ("ciphertext", "BLOB", 1, 0),
                ("key_id", "TEXT", 1, 0),
                ("scope_id", "TEXT", 1, 0),
                ("format_version", "INTEGER", 1, 0),
                ("content_hash", "TEXT", 1, 0),
                ("created_at", "REAL", 1, 0),
                ("effective_at", "REAL", 1, 0),
                ("superseded_by", "TEXT", 0, 0),
                ("superseded_at", "REAL", 0, 0),
                ("operation_state", "TEXT", 1, 0),
            ),
            "adapter_metadata": (
                ("key", "TEXT", 1, 1),
                ("value", "TEXT", 1, 0),
            ),
            "memory_vectors": (
                ("vine_id", "TEXT", 1, 1),
                ("ordinal", "INTEGER", 1, 2),
                ("nonce", "BLOB", 1, 0),
                ("ciphertext", "BLOB", 1, 0),
                ("dimension", "INTEGER", 1, 0),
                ("key_id", "TEXT", 1, 0),
                ("scope_id", "TEXT", 1, 0),
                ("format_version", "INTEGER", 1, 0),
            ),
            "memory_terms": (
                ("vine_id", "TEXT", 1, 1),
                ("term_hash", "BLOB", 1, 2),
                ("term_count", "INTEGER", 1, 0),
                ("key_id", "TEXT", 1, 0),
            ),
            "quarantine": (
                ("vine_id", "TEXT", 1, 1),
                ("reason_code", "TEXT", 1, 0),
                ("detected_at", "REAL", 1, 0),
            ),
            "deletion_tombstones": (
                ("vine_id", "TEXT", 1, 1),
                ("deleted_at", "REAL", 1, 0),
                ("key_id", "TEXT", 1, 0),
                ("scope_id", "TEXT", 1, 0),
                ("auth_tag", "BLOB", 1, 0),
            ),
        }
        for table, columns in expected.items():
            rows = self._connection.execute(f"PRAGMA table_xinfo({table})").fetchall()
            actual = tuple(
                (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
                for row in rows
                if int(row[6]) == 0
            )
            if actual != columns:
                raise RuntimeError("payload database schema validation failed")
        objects = {
            (str(row[0]), str(row[1]), str(row[2]))
            for row in self._connection.execute(
                "SELECT type, name, tbl_name FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        expected_objects = {
            *(("table", table, table) for table in expected),
            ("index", "idx_memory_terms_hash", "memory_terms"),
            ("index", "idx_payload_nonce", "payloads"),
            ("index", "idx_vector_nonce", "memory_vectors"),
        }
        if objects != expected_objects:
            raise RuntimeError("payload database schema validation failed")
        expected_indexes = {
            "idx_memory_terms_hash": ("term_hash",),
            "idx_payload_nonce": ("key_id", "nonce"),
            "idx_vector_nonce": ("key_id", "nonce"),
        }
        for index_name, expected_columns in expected_indexes.items():
            actual_index_columns = tuple(
                str(row[2])
                for row in self._connection.execute(f"PRAGMA index_info({index_name})")
            )
            if actual_index_columns != expected_columns:
                raise RuntimeError("payload database schema validation failed")

    def _verify_integrity(self) -> None:
        if not self._secure_schema:
            return super()._verify_integrity()
        rows = self._connection.execute("PRAGMA quick_check").fetchall()
        if tuple(str(row[0]) for row in rows) != ("ok",):
            raise RuntimeError("payload database integrity check failed")
        if self._connection.execute("PRAGMA foreign_key_check").fetchall():
            raise RuntimeError("payload database foreign-key integrity check failed")
        orphan_queries = (
            "SELECT 1 FROM memory_vectors AS child "
            "LEFT JOIN payloads ON payloads.vine_id = child.vine_id "
            "WHERE payloads.vine_id IS NULL LIMIT 1",
            "SELECT 1 FROM memory_terms AS child "
            "LEFT JOIN payloads ON payloads.vine_id = child.vine_id "
            "WHERE payloads.vine_id IS NULL LIMIT 1",
            "SELECT 1 FROM quarantine AS child "
            "LEFT JOIN payloads ON payloads.vine_id = child.vine_id "
            "WHERE payloads.vine_id IS NULL LIMIT 1",
        )
        for query in orphan_queries:
            if self._connection.execute(query).fetchone() is not None:
                raise RuntimeError(
                    "payload database foreign-key integrity check failed"
                )
        contract_orphan = self._connection.execute(
            """
            SELECT 1
            FROM adapter_metadata AS contract
            LEFT JOIN payloads
              ON contract.key = 'memory_contract:' || payloads.vine_id
            WHERE contract.key LIKE 'memory_contract:%'
              AND payloads.vine_id IS NULL
            LIMIT 1
            """
        ).fetchone()
        if contract_orphan is not None:
            raise RuntimeError(
                "payload database memory-contract integrity check failed"
            )
        contract_schema = self._connection.execute(
            """
            SELECT value FROM adapter_metadata
            WHERE key = 'memory_contract_schema'
            """
        ).fetchone()
        if (
            contract_schema is not None
            and str(contract_schema[0]) == MEMORY_CONTRACT_SCHEMA
        ):
            missing_contract = self._connection.execute(
                """
                SELECT 1
                FROM payloads
                LEFT JOIN adapter_metadata AS contract
                  ON contract.key = 'memory_contract:' || payloads.vine_id
                WHERE payloads.operation_state = 'committed'
                  AND contract.key IS NULL
                LIMIT 1
                """
            ).fetchone()
            if missing_contract is not None:
                raise RuntimeError(
                    "payload database memory-contract integrity check failed"
                )
        reused = self._connection.execute(
            """
            SELECT 1
            FROM payloads AS payload
            JOIN memory_vectors AS vector
              ON vector.key_id = payload.key_id
             AND vector.nonce = payload.nonce
            LIMIT 1
            """
        ).fetchone()
        if reused is not None:
            raise RuntimeError("payload database contains a reused AES-GCM nonce")
        if self._keyring is None:
            raise KeyUnavailable("secure profile keyring is unavailable")
        scope_id = self._keyring.scope_id
        key_ids = set(self._keyring.key_ids)
        rows = self._connection.execute(
            "SELECT vine_id, key_id, scope_id, format_version FROM payloads "
            "UNION ALL "
            "SELECT vine_id, key_id, scope_id, format_version FROM memory_vectors"
        ).fetchall()
        metadata_failures: set[str] = set()
        for vine_id, key_id, stored_scope, version in rows:
            if str(key_id) not in key_ids:
                raise KeyUnavailable("encrypted records reference an unavailable key")
            if str(stored_scope) != scope_id or int(version) != PAYLOAD_SCHEMA_VERSION:
                metadata_failures.add(str(vine_id))
        if metadata_failures and self._read_only:
            raise RuntimeError("encrypted record metadata authentication failed")
        for vine_id in metadata_failures:
            self._quarantine(vine_id, "record_metadata")
        if self._keyring.has_feature(RECORD_INTEGRITY_SCHEMA):
            if self.get_metadata("record_integrity_schema") != RECORD_INTEGRITY_SCHEMA:
                raise RuntimeError("required record integrity schema is missing")
            failures = self._verify_all_record_integrity()
            if failures and self._read_only:
                raise RuntimeError("authenticated record metadata verification failed")
            self._verify_tombstones()

    def topic_token(self, topic: str) -> str:
        if not self._secure_schema:
            return topic
        keyring = self._require_keyring()
        return opaque_topic(keyring.active_key(), keyring.scope_id, topic)

    def digest(self, topic: str, payload: str) -> str:
        if not self._secure_schema:
            return super().digest(topic, payload)
        keyring = self._require_keyring()
        return self._content_digest(keyring.active_key(), topic, payload)

    def _require_contract_shield(self) -> ScopedAesGcmShield:
        if self._contract_shield is None:
            raise RuntimeError("scoped memory-contract shield is unavailable")
        return self._contract_shield

    def _encode_memory_contract(
        self,
        vine_id: str,
        contract: MemoryLayerContract,
    ) -> str:
        if not isinstance(contract, MemoryLayerContract):
            raise TypeError("memory contract must be a MemoryLayerContract")
        protected = self._require_contract_shield().protect_blob_for_record(
            contract.to_json_bytes(),
            vine_id,
            object_type="memory-contract",
        )
        return protected.to_json_bytes().decode("ascii")

    def _decode_memory_contract(
        self,
        vine_id: str,
        encoded: str,
    ) -> MemoryLayerContract:
        try:
            protected = ScopedProtectedBlob.from_json_bytes(encoded.encode("ascii"))
            if (
                protected.record_id != vine_id
                or protected.object_type != "memory-contract"
            ):
                raise ValueError("memory contract record binding is invalid")
            plaintext = bytearray(
                self._require_contract_shield().reveal_blob(protected)
            )
            try:
                return MemoryLayerContract.from_json_bytes(bytes(plaintext))
            finally:
                for index in range(len(plaintext)):
                    plaintext[index] = 0
        except Exception as exc:
            self._quarantine(vine_id, "memory_contract_authentication")
            raise QuarantinedRecordError(
                "protected memory contract is quarantined"
            ) from exc

    def initialize_memory_contracts(self) -> int:
        """Attach shielded short-term contracts to pre-contract secure records."""

        if not self._secure_schema:
            return 0
        keyring = self._require_keyring()
        feature_enabled = keyring.has_feature(MEMORY_CONTRACT_SCHEMA)
        stored_schema = self.get_metadata("memory_contract_schema")
        if stored_schema not in {None, MEMORY_CONTRACT_SCHEMA}:
            raise RuntimeError("memory contract schema is unsupported")
        if feature_enabled and stored_schema != MEMORY_CONTRACT_SCHEMA:
            raise RuntimeError("required protected memory contract schema is missing")
        contract_count_row = self._connection.execute(
            """
            SELECT COUNT(*) FROM adapter_metadata
            WHERE key LIKE 'memory_contract:%'
            """
        ).fetchone()
        contract_count = 0 if contract_count_row is None else int(contract_count_row[0])
        if stored_schema is None and contract_count:
            raise RuntimeError(
                "memory contract schema marker is missing from a protected profile"
            )
        rows = self._connection.execute(
            """
            SELECT vine_id, created_at
            FROM payloads
            WHERE operation_state = 'committed'
            ORDER BY created_at, vine_id
            """
        ).fetchall()
        missing: list[tuple[str, str]] = []
        for vine_id_raw, created_at_raw in rows:
            vine_id = str(vine_id_raw)
            existing = self.get_metadata(_memory_contract_key(vine_id))
            if existing is not None:
                self._decode_memory_contract(vine_id, existing)
                continue
            if stored_schema == MEMORY_CONTRACT_SCHEMA:
                self._quarantine(vine_id, "memory_contract_missing")
                raise RuntimeError("protected memory contract is missing")
            contract = migrated_short_term_contract(
                created_at=_validate_stored_timestamp(created_at_raw, "created_at")
            )
            missing.append((vine_id, self._encode_memory_contract(vine_id, contract)))
        if self._read_only:
            if (
                not feature_enabled
                or stored_schema != MEMORY_CONTRACT_SCHEMA
                or missing
            ):
                raise RuntimeError(
                    "always-available recall requires migrated shielded layer contracts"
                )
            return 0
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.executemany(
                "INSERT INTO adapter_metadata(key, value) VALUES (?, ?)",
                [(_memory_contract_key(vine_id), value) for vine_id, value in missing],
            )
            self._connection.execute(
                """
                INSERT INTO adapter_metadata(key, value)
                VALUES ('memory_contract_schema', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (MEMORY_CONTRACT_SCHEMA,),
            )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise
        keyring.enable_feature(MEMORY_CONTRACT_SCHEMA)
        return len(missing)

    def initialize_record_integrity(self) -> int:
        """Adopt or verify authenticated lifecycle and retrieval metadata."""

        if not self._secure_schema:
            return 0
        keyring = self._require_keyring()
        feature_enabled = keyring.has_feature(RECORD_INTEGRITY_SCHEMA)
        stored_schema = self.get_metadata("record_integrity_schema")
        if stored_schema not in {None, RECORD_INTEGRITY_SCHEMA}:
            raise RuntimeError("record integrity schema is unsupported")
        tag_rows = self._connection.execute(
            "SELECT key FROM adapter_metadata WHERE key LIKE ? ORDER BY key",
            (f"{RECORD_INTEGRITY_METADATA_PREFIX}%",),
        ).fetchall()
        record_ids = [
            str(row[0])
            for row in self._connection.execute(
                "SELECT vine_id FROM payloads ORDER BY created_at, vine_id"
            ).fetchall()
        ]
        if feature_enabled:
            if stored_schema != RECORD_INTEGRITY_SCHEMA:
                raise RuntimeError("required record integrity schema is missing")
            if self._verify_all_record_integrity() and self._read_only:
                raise RuntimeError("authenticated record metadata verification failed")
            self._verify_tombstones()
            return 0
        if stored_schema == RECORD_INTEGRITY_SCHEMA:
            if len(tag_rows) != len(record_ids) or self._verify_all_record_integrity():
                raise RuntimeError("record integrity migration is incomplete")
            self._verify_tombstones()
            keyring.enable_feature(RECORD_INTEGRITY_SCHEMA)
            return 0
        if tag_rows:
            raise RuntimeError("record integrity migration is incomplete")
        if self._read_only:
            raise RuntimeError(
                "always-available recall requires authenticated record metadata"
            )

        for vine_id in record_ids:
            self._validate_record_before_integrity_adoption(vine_id)
        self._verify_tombstones()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            for vine_id in record_ids:
                self._write_record_integrity(vine_id)
            self._connection.execute(
                """
                INSERT INTO adapter_metadata(key, value)
                VALUES ('record_integrity_schema', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (RECORD_INTEGRITY_SCHEMA,),
            )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise
        keyring.enable_feature(RECORD_INTEGRITY_SCHEMA)
        return len(record_ids)

    def _validate_record_before_integrity_adoption(self, vine_id: str) -> None:
        record = self.get_record(vine_id)
        if record is None:
            raise RuntimeError("record disappeared during integrity migration")
        self.get_memory_contract(vine_id)
        row = self._connection.execute(
            "SELECT content_hash, key_id FROM payloads WHERE vine_id = ?",
            (vine_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("record disappeared during integrity migration")
        payload_key_id = str(row[1])
        keyring = self._require_keyring()
        expected_content_hash = self._content_digest(
            keyring.key(payload_key_id),
            record[0],
            record[1],
        )
        if not hmac.compare_digest(str(row[0]), expected_content_hash):
            raise RuntimeError("record content digest is corrupt")
        vector_rows = self._connection.execute(
            """
            SELECT ordinal, CAST(nonce AS BLOB), CAST(ciphertext AS BLOB),
                   dimension, key_id, scope_id, format_version
            FROM memory_vectors WHERE vine_id = ? ORDER BY ordinal
            """,
            (vine_id,),
        ).fetchall()
        for vector_row in vector_rows:
            vector = self._decrypt_vector(
                vine_id=vine_id,
                ordinal=int(vector_row[0]),
                nonce=bytes(vector_row[1]),
                ciphertext=bytes(vector_row[2]),
                dimension=int(vector_row[3]),
                key_id=str(vector_row[4]),
                scope_id=str(vector_row[5]),
                format_version=int(vector_row[6]),
            )
            vector.fill(0.0)
        term_rows = self._connection.execute(
            """
            SELECT CAST(term_hash AS BLOB), term_count, key_id
            FROM memory_terms WHERE vine_id = ? ORDER BY term_hash
            """,
            (vine_id,),
        ).fetchall()
        term_key_ids = {str(term_row[2]) for term_row in term_rows}
        if len(term_key_ids) > 1:
            raise RuntimeError("record term index mixes authentication keys")
        if term_key_ids:
            term_key_id = next(iter(term_key_ids))
            expected_terms = self._term_features_for_key(
                f"{record[0]}\n{record[1]}",
                MAX_LEXICAL_FEATURES,
                keyring.key(term_key_id),
            )
            actual_terms = {
                bytes(term_hash): int(term_count)
                for term_hash, term_count, _key_id in term_rows
            }
            if actual_terms != expected_terms:
                raise RuntimeError("record term index is corrupt")

    def _record_integrity_message(self, vine_id: str) -> tuple[str, bytes]:
        payload = self._connection.execute(
            """
            SELECT topic, CAST(nonce AS BLOB), CAST(ciphertext AS BLOB),
                   key_id, scope_id, format_version, content_hash,
                   created_at, effective_at, superseded_by, superseded_at,
                   operation_state
            FROM payloads WHERE vine_id = ?
            """,
            (vine_id,),
        ).fetchone()
        if payload is None:
            raise KeyError("memory does not exist")
        contract = self._connection.execute(
            "SELECT value FROM adapter_metadata WHERE key = ?",
            (_memory_contract_key(vine_id),),
        ).fetchone()
        if contract is None:
            raise RuntimeError("protected memory contract is missing")
        vectors = self._connection.execute(
            """
            SELECT ordinal, CAST(nonce AS BLOB), CAST(ciphertext AS BLOB),
                   dimension, key_id, scope_id, format_version
            FROM memory_vectors WHERE vine_id = ? ORDER BY ordinal
            """,
            (vine_id,),
        ).fetchall()
        terms = self._connection.execute(
            """
            SELECT CAST(term_hash AS BLOB), term_count, key_id
            FROM memory_terms WHERE vine_id = ? ORDER BY term_hash
            """,
            (vine_id,),
        ).fetchall()
        key_id = str(payload[3])
        message = json.dumps(
            {
                "contract_sha256": hashlib.sha256(
                    str(contract[0]).encode("ascii")
                ).hexdigest(),
                "payload": {
                    "ciphertext_sha256": hashlib.sha256(bytes(payload[2])).hexdigest(),
                    "content_hash": str(payload[6]),
                    "created_at": float(payload[7]),
                    "effective_at": float(payload[8]),
                    "format_version": int(payload[5]),
                    "key_id": key_id,
                    "nonce": bytes(payload[1]).hex(),
                    "operation_state": str(payload[11]),
                    "scope_id": str(payload[4]),
                    "superseded_at": (
                        None if payload[10] is None else float(payload[10])
                    ),
                    "superseded_by": (None if payload[9] is None else str(payload[9])),
                    "topic": str(payload[0]),
                },
                "record_id": vine_id,
                "schema": RECORD_INTEGRITY_SCHEMA,
                "terms": [
                    {
                        "count": int(term[1]),
                        "hash": bytes(term[0]).hex(),
                        "key_id": str(term[2]),
                    }
                    for term in terms
                ],
                "vectors": [
                    {
                        "ciphertext_sha256": hashlib.sha256(
                            bytes(vector[2])
                        ).hexdigest(),
                        "dimension": int(vector[3]),
                        "format_version": int(vector[6]),
                        "key_id": str(vector[4]),
                        "nonce": bytes(vector[1]).hex(),
                        "ordinal": int(vector[0]),
                        "scope_id": str(vector[5]),
                    }
                    for vector in vectors
                ],
            },
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return key_id, message

    def _record_integrity_tag(self, vine_id: str) -> tuple[str, bytes]:
        key_id, message = self._record_integrity_message(vine_id)
        keyring = self._require_keyring()
        derived_key = hmac.new(
            keyring.key(key_id),
            b"echo-veil-record-integrity-key-v1\0" + keyring.scope_id.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return key_id, hmac.new(
            derived_key,
            b"echo-veil-record-integrity-v1\0" + message,
            hashlib.sha256,
        ).digest()

    def _write_record_integrity(self, vine_id: str) -> None:
        key_id, tag = self._record_integrity_tag(vine_id)
        value = json.dumps(
            {
                "key_id": key_id,
                "schema": RECORD_INTEGRITY_SCHEMA,
                "tag": tag.hex(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self._connection.execute(
            """
            INSERT INTO adapter_metadata(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (_record_integrity_key(vine_id), value),
        )

    def _refresh_record_integrity(self, vine_id: str) -> None:
        if self._require_keyring().has_feature(RECORD_INTEGRITY_SCHEMA):
            self._write_record_integrity(vine_id)

    def _verify_record_integrity(self, vine_id: str) -> None:
        if not self._require_keyring().has_feature(RECORD_INTEGRITY_SCHEMA):
            return
        row = self._connection.execute(
            "SELECT value FROM adapter_metadata WHERE key = ?",
            (_record_integrity_key(vine_id),),
        ).fetchone()
        try:
            if row is None:
                raise ValueError("record integrity tag is missing")
            decoded = strict_json_loads(str(row[0]))
            if not isinstance(decoded, dict) or set(decoded) != {
                "key_id",
                "schema",
                "tag",
            }:
                raise ValueError("record integrity tag fields are invalid")
            if decoded["schema"] != RECORD_INTEGRITY_SCHEMA:
                raise ValueError("record integrity schema is invalid")
            encoded_tag = decoded["tag"]
            if (
                not isinstance(encoded_tag, str)
                or re.fullmatch(r"[0-9a-f]{64}", encoded_tag) is None
            ):
                raise ValueError("record integrity tag encoding is invalid")
            expected_key_id, expected_tag = self._record_integrity_tag(vine_id)
            if decoded["key_id"] != expected_key_id or not hmac.compare_digest(
                bytes.fromhex(encoded_tag),
                expected_tag,
            ):
                raise ValueError("record integrity authentication failed")
        except Exception as exc:
            self._quarantine(vine_id, "record_integrity")
            raise QuarantinedRecordError(
                "authenticated record metadata is quarantined"
            ) from exc

    def _verify_all_record_integrity(self) -> list[str]:
        failures: list[str] = []
        rows = self._connection.execute(
            "SELECT vine_id FROM payloads ORDER BY vine_id"
        ).fetchall()
        for row in rows:
            vine_id = str(row[0])
            try:
                self._verify_record_integrity(vine_id)
            except QuarantinedRecordError:
                failures.append(vine_id)
        return failures

    def _verify_tombstones(self) -> int:
        if not self._secure_schema:
            return 0
        keyring = self._require_keyring()
        rows = self._connection.execute(
            """
            SELECT vine_id, deleted_at, key_id, scope_id,
                   CAST(auth_tag AS BLOB)
            FROM deletion_tombstones ORDER BY vine_id
            """
        ).fetchall()
        for vine_id_raw, deleted_at_raw, key_id_raw, scope_id_raw, tag_raw in rows:
            vine_id = _validate_text(str(vine_id_raw), "tombstone vine_id", 128)
            deleted_at = _validate_stored_timestamp(deleted_at_raw, "deleted_at")
            key_id = str(key_id_raw)
            scope_id = str(scope_id_raw)
            if scope_id != keyring.scope_id:
                raise RuntimeError("authenticated deletion scope is corrupt")
            expected = self._tombstone_tag(
                keyring.key(key_id),
                vine_id,
                deleted_at,
                scope_id,
                key_id,
            )
            if not hmac.compare_digest(expected, bytes(tag_raw)):
                raise RuntimeError("authenticated deletion state is corrupt")
        return len(rows)

    def get_memory_contract(self, vine_id: str) -> MemoryLayerContract:
        if not self._secure_schema:
            return super().get_memory_contract(vine_id)
        self._verify_record_integrity(vine_id)
        row = self._connection.execute(
            "SELECT value FROM adapter_metadata WHERE key = ?",
            (_memory_contract_key(vine_id),),
        ).fetchone()
        if row is None:
            self._quarantine(vine_id, "memory_contract_missing")
            raise QuarantinedRecordError("protected memory contract is missing")
        return self._decode_memory_contract(vine_id, str(row[0]))

    def set_memory_contract(
        self,
        vine_id: str,
        contract: MemoryLayerContract,
    ) -> None:
        if not self._secure_schema:
            return super().set_memory_contract(vine_id, contract)
        value = self._encode_memory_contract(vine_id, contract)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            exists = self._connection.execute(
                """
                SELECT 1 FROM payloads
                WHERE vine_id = ? AND operation_state = 'committed'
                """,
                (vine_id,),
            ).fetchone()
            if exists is None:
                raise KeyError("memory does not exist")
            self._connection.execute(
                """
                INSERT INTO adapter_metadata(key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (_memory_contract_key(vine_id), value),
            )
            self._refresh_record_integrity(vine_id)
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def memory_contract_counts(self) -> dict[str, int]:
        counts = {layer.value: 0 for layer in MemoryLayer}
        if not self._secure_schema:
            return counts
        rows = self._connection.execute(
            """
            SELECT payloads.vine_id, adapter_metadata.value
            FROM payloads
            JOIN adapter_metadata
              ON adapter_metadata.key = 'memory_contract:' || payloads.vine_id
            LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id
            WHERE payloads.operation_state = 'committed'
              AND quarantine.vine_id IS NULL
            ORDER BY payloads.created_at, payloads.vine_id
            """
        ).fetchall()
        for vine_id_raw, encoded_raw in rows:
            try:
                self._verify_record_integrity(str(vine_id_raw))
            except QuarantinedRecordError:
                continue
            contract = self._decode_memory_contract(
                str(vine_id_raw),
                str(encoded_raw),
            )
            counts[contract.layer.value] += 1
        return counts

    def find_duplicate(self, topic: str, payload: str) -> tuple[str, str] | None:
        if not self._secure_schema:
            return super().find_by_hash(super().digest(topic, payload))
        keyring = self._require_keyring()
        for key_id in keyring.key_ids:
            content_hash = self._content_digest(
                keyring.key(key_id),
                topic,
                payload,
            )
            row = self._connection.execute(
                """
                SELECT payloads.vine_id
                FROM payloads
                LEFT JOIN quarantine
                  ON quarantine.vine_id = payloads.vine_id
                WHERE payloads.content_hash = ?
                  AND payloads.operation_state = 'committed'
                  AND quarantine.vine_id IS NULL
                """,
                (content_hash,),
            ).fetchone()
            if row is None:
                continue
            record = self.get_record(str(row[0]))
            if record is not None and hmac.compare_digest(
                record[0].encode("utf-8"),
                topic.encode("utf-8"),
            ):
                if hmac.compare_digest(
                    record[1].encode("utf-8"),
                    payload.encode("utf-8"),
                ):
                    return str(row[0]), record[0]
        return None

    def find_by_hash(self, content_hash: str) -> tuple[str, str] | None:
        if not self._secure_schema:
            return super().find_by_hash(content_hash)
        row = self._connection.execute(
            """
            SELECT payloads.vine_id
            FROM payloads
            LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id
            WHERE payloads.content_hash = ?
              AND payloads.operation_state = 'committed'
              AND quarantine.vine_id IS NULL
            """,
            (content_hash,),
        ).fetchone()
        if row is None:
            return None
        record = self.get_record(str(row[0]))
        return None if record is None else (str(row[0]), record[0])

    def put(
        self,
        vine_id: str,
        topic: str,
        payload: str,
        content_hash: str,
        *,
        vectors: list[NDArray[np.float64]],
        effective_at: float,
        supersedes: tuple[str, ...],
        contract: MemoryLayerContract | None = None,
    ) -> None:
        if not self._secure_schema:
            return super().put(
                vine_id,
                topic,
                payload,
                content_hash,
                vectors=vectors,
                effective_at=effective_at,
                supersedes=supersedes,
                contract=contract,
            )
        if not isinstance(contract, MemoryLayerContract):
            raise TypeError("secure memories require a protected layer contract")
        keyring = self._require_keyring()
        key_id = keyring.active_key_id
        key = keyring.active_key()
        scope_id = keyring.scope_id
        expected_content_hash = self._content_digest(key, topic, payload)
        if not hmac.compare_digest(content_hash, expected_content_hash):
            raise ValueError("content hash does not match the protected record")
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        envelope = self._encode_envelope(
            vine_id=vine_id,
            topic=topic,
            payload=payload,
            key_id=key_id,
            scope_id=scope_id,
        )
        ciphertext = AESGCM(key).encrypt(
            nonce,
            envelope,
            scoped_aad(
                object_type="payload",
                scope_id=scope_id,
                record_id=vine_id,
                schema_version=PAYLOAD_SCHEMA_VERSION,
                key_id=key_id,
            ),
        )
        topic_value = opaque_topic(key, scope_id, topic)
        created_at = time.time()
        terms = self._term_features_for_key(
            f"{topic}\n{payload}",
            MAX_LEXICAL_FEATURES,
            key,
        )
        contract_value = self._encode_memory_contract(vine_id, contract)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            for prior_id in supersedes:
                self._verify_record_integrity(prior_id)
                row = self._connection.execute(
                    """
                    SELECT effective_at, superseded_by
                    FROM payloads
                    WHERE vine_id = ? AND operation_state = 'committed'
                    """,
                    (prior_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"superseded memory does not exist: {prior_id}")
                if row[1] is not None:
                    raise ValueError(f"memory is already superseded: {prior_id}")
                if float(row[0]) > effective_at:
                    raise ValueError(
                        "replacement effective_at must not precede superseded memory"
                    )
            self._connection.execute(
                """
                INSERT INTO payloads(
                    vine_id, topic, nonce, ciphertext, key_id, scope_id,
                    format_version, content_hash, created_at, effective_at,
                    superseded_by, superseded_at, operation_state
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 'pending')
                """,
                (
                    vine_id,
                    topic_value,
                    nonce,
                    ciphertext,
                    key_id,
                    scope_id,
                    PAYLOAD_SCHEMA_VERSION,
                    content_hash,
                    created_at,
                    effective_at,
                ),
            )
            for ordinal, vector in enumerate(vectors):
                clean = _normalize_embedding_vector(vector)
                vector_nonce = os.urandom(AES_GCM_NONCE_BYTES)
                vector_ciphertext = AESGCM(key).encrypt(
                    vector_nonce,
                    clean.astype(np.float64, copy=False).tobytes(order="C"),
                    scoped_aad(
                        object_type="retrieval-vector",
                        scope_id=scope_id,
                        record_id=vine_id,
                        schema_version=PAYLOAD_SCHEMA_VERSION,
                        key_id=key_id,
                        ordinal=ordinal,
                        dimension=int(clean.size),
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO memory_vectors(
                        vine_id, ordinal, nonce, ciphertext, dimension,
                        key_id, scope_id, format_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vine_id,
                        ordinal,
                        vector_nonce,
                        vector_ciphertext,
                        clean.size,
                        key_id,
                        scope_id,
                        PAYLOAD_SCHEMA_VERSION,
                    ),
                )
            self._connection.executemany(
                """
                INSERT INTO memory_terms(
                    vine_id, term_hash, term_count, key_id
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (vine_id, term_hash, count, key_id)
                    for term_hash, count in terms.items()
                ],
            )
            self._connection.execute(
                """
                INSERT INTO adapter_metadata(key, value)
                VALUES (?, ?)
                """,
                (_memory_contract_key(vine_id), contract_value),
            )
            for prior_id in supersedes:
                self._connection.execute(
                    """
                    UPDATE payloads
                    SET superseded_by = ?, superseded_at = ?
                    WHERE vine_id = ?
                      AND superseded_by IS NULL
                      AND operation_state = 'committed'
                    """,
                    (vine_id, effective_at, prior_id),
                )
                self._refresh_record_integrity(prior_id)
            self._refresh_record_integrity(vine_id)
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def mark_committed(self, vine_id: str) -> None:
        if not self._secure_schema:
            return
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._verify_record_integrity(vine_id)
            result = self._connection.execute(
                """
                UPDATE payloads
                SET operation_state = 'committed'
                WHERE vine_id = ? AND operation_state = 'pending'
                """,
                (vine_id,),
            )
            if result.rowcount != 1:
                raise RuntimeError("pending encrypted record could not be committed")
            self._refresh_record_integrity(vine_id)
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def pending_ids(self) -> list[str]:
        if not self._secure_schema:
            return []
        rows = self._connection.execute(
            "SELECT vine_id FROM payloads WHERE operation_state = 'pending' "
            "ORDER BY vine_id"
        ).fetchall()
        result: list[str] = []
        for row in rows:
            vine_id = str(row[0])
            self._verify_record_integrity(vine_id)
            result.append(vine_id)
        return result

    def get_record(self, vine_id: str) -> tuple[str, str] | None:
        if not self._secure_schema:
            row = self._connection.execute(
                "SELECT topic FROM payloads WHERE vine_id = ?",
                (vine_id,),
            ).fetchone()
            payload = super().get(vine_id)
            if row is None or payload is None:
                return None
            return _validate_stored_topic(row[0]), payload
        exists = self._connection.execute(
            "SELECT 1 FROM payloads WHERE vine_id = ?",
            (vine_id,),
        ).fetchone()
        if exists is None:
            return None
        self._verify_record_integrity(vine_id)
        row = self._connection.execute(
            """
            SELECT topic, CAST(nonce AS BLOB), CAST(ciphertext AS BLOB),
                   key_id, scope_id, format_version
            FROM payloads
            WHERE vine_id = ? AND operation_state = 'committed'
            """,
            (vine_id,),
        ).fetchone()
        if row is None:
            return None
        stored_topic_token = _validate_stored_topic(row[0])
        record = self._decrypt_record(vine_id, row[1:])
        keyring = self._require_keyring()
        expected_topic_token = opaque_topic(
            keyring.key(str(row[3])),
            str(row[4]),
            record[0],
        )
        if not hmac.compare_digest(stored_topic_token, expected_topic_token):
            self._quarantine(vine_id, "topic_binding")
            raise QuarantinedRecordError("encrypted record is quarantined")
        return record

    def get_record_details(self, vine_id: str) -> dict[str, Any] | None:
        """Return one authenticated record with its bounded temporal metadata."""

        clean_id = _validate_text(vine_id, "vine_id", 128)
        if not self._secure_schema:
            row = self._connection.execute(
                """
                SELECT effective_at, superseded_by, superseded_at
                FROM payloads
                WHERE vine_id = ?
                """,
                (clean_id,),
            ).fetchone()
        else:
            row = self._connection.execute(
                """
                SELECT payloads.effective_at, payloads.superseded_by,
                       payloads.superseded_at
                FROM payloads
                LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id
                WHERE payloads.vine_id = ?
                  AND payloads.operation_state = 'committed'
                  AND quarantine.vine_id IS NULL
                """,
                (clean_id,),
            ).fetchone()
        if row is None:
            return None
        record = self.get_record(clean_id)
        if record is None:
            return None
        return {
            "vine_id": clean_id,
            "topic": record[0],
            "payload": record[1],
            "effective_at": _validate_stored_timestamp(row[0], "effective_at"),
            "superseded_by": None if row[1] is None else str(row[1]),
            "superseded_at": (
                None
                if row[2] is None
                else _validate_stored_timestamp(row[2], "superseded_at")
            ),
        }

    def _get_pending_record(self, vine_id: str) -> tuple[str, str] | None:
        self._verify_record_integrity(vine_id)
        row = self._connection.execute(
            """
            SELECT CAST(nonce AS BLOB), CAST(ciphertext AS BLOB),
                   key_id, scope_id, format_version
            FROM payloads
            WHERE vine_id = ?
            """,
            (vine_id,),
        ).fetchone()
        if row is None:
            return None
        return self._decrypt_record(vine_id, row)

    def get(self, vine_id: str) -> str | None:
        if not self._secure_schema:
            return super().get(vine_id)
        record = self.get_record(vine_id)
        return None if record is None else record[1]

    def get_topic(self, vine_id: str) -> str | None:
        record = self.get_record(vine_id)
        return None if record is None else record[0]

    def delete(self, vine_id: str, *, tombstone: bool = True) -> bool:
        if not self._secure_schema:
            return super().delete(vine_id)
        keyring = self._require_keyring()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._verify_tombstones()
            link = self._connection.execute(
                """
                SELECT superseded_by, superseded_at, key_id, operation_state
                FROM payloads WHERE vine_id = ?
                """,
                (vine_id,),
            ).fetchone()
            if link is None:
                self._connection.execute("ROLLBACK")
                return False
            self._verify_record_integrity(vine_id)
            affected_rows = self._connection.execute(
                "SELECT vine_id FROM payloads WHERE superseded_by = ? ORDER BY vine_id",
                (vine_id,),
            ).fetchall()
            affected_ids = [str(row[0]) for row in affected_rows]
            for affected_id in affected_ids:
                self._verify_record_integrity(affected_id)
            if tombstone and str(link[3]) == "committed":
                deleted_at = time.time()
                key_id = keyring.active_key_id
                tag = self._tombstone_tag(
                    keyring.key(key_id),
                    vine_id,
                    deleted_at,
                    keyring.scope_id,
                    key_id,
                )
                self._connection.execute(
                    """
                    INSERT INTO deletion_tombstones(
                        vine_id, deleted_at, key_id, scope_id, auth_tag
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(vine_id) DO UPDATE SET
                        deleted_at = excluded.deleted_at,
                        key_id = excluded.key_id,
                        scope_id = excluded.scope_id,
                        auth_tag = excluded.auth_tag
                    """,
                    (vine_id, deleted_at, key_id, keyring.scope_id, tag),
                )
            self._connection.execute(
                "DELETE FROM quarantine WHERE vine_id = ?", (vine_id,)
            )
            self._connection.execute(
                "DELETE FROM memory_vectors WHERE vine_id = ?", (vine_id,)
            )
            self._connection.execute(
                "DELETE FROM memory_terms WHERE vine_id = ?", (vine_id,)
            )
            self._connection.execute(
                "DELETE FROM adapter_metadata WHERE key = ?",
                (_memory_contract_key(vine_id),),
            )
            self._connection.execute(
                "DELETE FROM adapter_metadata WHERE key = ?",
                (_record_integrity_key(vine_id),),
            )
            self._connection.execute(
                """
                UPDATE payloads
                SET superseded_by = ?, superseded_at = ?
                WHERE superseded_by = ?
                """,
                (link[0], link[1], vine_id),
            )
            for affected_id in affected_ids:
                self._refresh_record_integrity(affected_id)
            result = self._connection.execute(
                "DELETE FROM payloads WHERE vine_id = ?", (vine_id,)
            )
            self._connection.execute("COMMIT")
            return result.rowcount > 0
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def retrieval_candidates(
        self,
        intent: NDArray[np.float64],
        query: str,
        semantic_candidate_ids: list[str],
        answerability_intent: NDArray[np.float64] | None = None,
    ) -> dict[str, _StoredCandidate]:
        if not self._secure_schema:
            return super().retrieval_candidates(
                intent,
                query,
                semantic_candidate_ids,
                answerability_intent,
            )
        query_vector = _normalize_embedding_vector(intent)
        answerability_vector = (
            None
            if answerability_intent is None
            else _normalize_embedding_vector(
                answerability_intent,
                expected_dimension=query_vector.size,
                source="answerability embedder",
            )
        )
        lexical = self._lexical_scores(query)
        ordered_ids = list(dict.fromkeys(semantic_candidate_ids))[
            :MAX_RETRIEVAL_CANDIDATES
        ]
        candidate_ids = set(ordered_ids)
        for vine_id in sorted(
            lexical,
            key=lambda candidate: (lexical[candidate], candidate),
            reverse=True,
        ):
            if len(candidate_ids) >= MAX_RETRIEVAL_CANDIDATES:
                break
            candidate_ids.add(vine_id)
        authenticated_ids: set[str] = set()
        for vine_id in candidate_ids:
            try:
                self._verify_record_integrity(vine_id)
            except QuarantinedRecordError:
                continue
            authenticated_ids.add(vine_id)
        candidate_ids = authenticated_ids
        if not candidate_ids:
            return {}
        placeholders = ",".join("?" for _ in candidate_ids)
        parameters = tuple(sorted(candidate_ids))
        semantic: dict[str, tuple[float, NDArray[np.float64]]] = {}
        answerability: dict[str, float] = {}
        bad_ids: set[str] = set()
        vector_query = (
            "SELECT vector.vine_id, vector.ordinal, "
            "CAST(vector.nonce AS BLOB), CAST(vector.ciphertext AS BLOB), "
            "vector.dimension, vector.key_id, "
            "vector.scope_id, vector.format_version "
            "FROM memory_vectors AS vector "
            "JOIN payloads AS payload ON payload.vine_id = vector.vine_id "
            "LEFT JOIN quarantine ON quarantine.vine_id = vector.vine_id "
            f"WHERE vector.vine_id IN ({placeholders}) "
            "AND payload.operation_state = 'committed' "
            "AND quarantine.vine_id IS NULL "
            "ORDER BY vector.vine_id, vector.ordinal"
        )
        for row in self._connection.execute(vector_query, parameters):
            vine_id = str(row[0])
            ordinal = int(row[1])
            dimension = int(row[4])
            try:
                vector = self._decrypt_vector(
                    vine_id=vine_id,
                    ordinal=ordinal,
                    nonce=bytes(row[2]),
                    ciphertext=bytes(row[3]),
                    dimension=dimension,
                    key_id=str(row[5]),
                    scope_id=str(row[6]),
                    format_version=int(row[7]),
                )
            except (QuarantinedRecordError, KeyUnavailable):
                bad_ids.add(vine_id)
                self._quarantine(vine_id, "retrieval_vector_authentication")
                continue
            if dimension != query_vector.size:
                bad_ids.add(vine_id)
                self._quarantine(vine_id, "retrieval_vector_dimension")
                continue
            score = cosine_similarity(query_vector, vector)
            current = semantic.get(vine_id)
            if current is None or score > current[0]:
                semantic[vine_id] = (score, vector)
            if answerability_vector is not None:
                answerability_score = cosine_similarity(answerability_vector, vector)
                current_answerability = answerability.get(vine_id)
                if (
                    current_answerability is None
                    or answerability_score > current_answerability
                ):
                    answerability[vine_id] = answerability_score
        payload_query = (
            "SELECT payloads.vine_id, payloads.topic, payloads.effective_at, "
            "payloads.superseded_by, payloads.superseded_at "
            "FROM payloads "
            "LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id "
            f"WHERE payloads.vine_id IN ({placeholders}) "
            "AND payloads.operation_state = 'committed' "
            "AND quarantine.vine_id IS NULL"
        )
        rows = self._connection.execute(payload_query, parameters).fetchall()
        candidates: dict[str, _StoredCandidate] = {}
        for row in rows:
            vine_id = str(row[0])
            if vine_id in bad_ids:
                continue
            semantic_entry = semantic.get(vine_id)
            effective_at = _validate_stored_timestamp(row[2], "effective_at")
            superseded_at = (
                None
                if row[4] is None
                else _validate_stored_timestamp(row[4], "superseded_at")
            )
            candidates[vine_id] = _StoredCandidate(
                vine_id=vine_id,
                semantic_score=None if semantic_entry is None else semantic_entry[0],
                answerability_score=answerability.get(vine_id),
                lexical_score=lexical.get(vine_id, 0.0),
                best_vector=None if semantic_entry is None else semantic_entry[1],
                topic=_validate_stored_topic(row[1]),
                effective_at=effective_at,
                superseded_by=None if row[3] is None else str(row[3]),
                superseded_at=superseded_at,
            )
        return candidates

    def retrieval_index_counts(self) -> tuple[int, int]:
        if not self._secure_schema:
            return super().retrieval_index_counts()
        indexed_row = self._connection.execute(
            """
            SELECT COUNT(DISTINCT memory_vectors.vine_id)
            FROM memory_vectors
            JOIN payloads ON payloads.vine_id = memory_vectors.vine_id
            LEFT JOIN quarantine ON quarantine.vine_id = memory_vectors.vine_id
            WHERE payloads.operation_state = 'committed'
              AND quarantine.vine_id IS NULL
            """
        ).fetchone()
        total = len(self)
        indexed = 0 if indexed_row is None else int(indexed_row[0])
        return indexed, max(0, total - indexed)

    def record_ids_for_reindex(self) -> list[str]:
        if not self._secure_schema:
            return super().record_ids_for_reindex()
        rows = self._connection.execute(
            """
            SELECT payloads.vine_id
            FROM payloads
            LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id
            WHERE payloads.operation_state = 'committed'
              AND quarantine.vine_id IS NULL
            ORDER BY payloads.created_at, payloads.vine_id
            """
        ).fetchall()
        record_ids: list[str] = []
        for row in rows:
            vine_id = str(row[0])
            try:
                self._verify_record_integrity(vine_id)
            except QuarantinedRecordError:
                continue
            record_ids.append(vine_id)
        return record_ids

    def record_for_reindex(self, vine_id: str) -> tuple[str, str]:
        if not self._secure_schema:
            return super().record_for_reindex(vine_id)
        record = self.get_record(vine_id)
        if record is None:
            raise RuntimeError("payload disappeared during retrieval reindex")
        return record

    def records_for_migration(self) -> list[_MigrationRecord]:
        if not self._secure_schema:
            return super().records_for_migration()
        rows = self._connection.execute(
            """
            SELECT payloads.vine_id, payloads.effective_at, payloads.superseded_by
            FROM payloads
            LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id
            WHERE payloads.operation_state = 'committed'
              AND quarantine.vine_id IS NULL
            ORDER BY payloads.created_at, payloads.vine_id
            """
        ).fetchall()
        records: list[_MigrationRecord] = []
        for row in rows:
            vine_id = str(row[0])
            record = self.get_record(vine_id)
            if record is None:
                raise RuntimeError("payload disappeared during profile migration")
            records.append(
                _MigrationRecord(
                    vine_id=vine_id,
                    topic=record[0],
                    effective_at=_validate_stored_timestamp(row[1], "effective_at"),
                    superseded_by=None if row[2] is None else str(row[2]),
                )
            )
        return records

    def replace_retrieval_index(
        self,
        vine_id: str,
        text: str,
        vectors: list[NDArray[np.float64]],
    ) -> None:
        if not self._secure_schema:
            return super().replace_retrieval_index(vine_id, text, vectors)
        keyring = self._require_keyring()
        key_id = keyring.active_key_id
        key = keyring.active_key()
        terms = self._term_features_for_key(text, MAX_LEXICAL_FEATURES, key)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._verify_record_integrity(vine_id)
            exists = self._connection.execute(
                """
                SELECT 1 FROM payloads
                WHERE vine_id = ? AND operation_state = 'committed'
                """,
                (vine_id,),
            ).fetchone()
            if exists is None:
                raise RuntimeError("payload disappeared during retrieval reindex")
            self._connection.execute(
                "DELETE FROM memory_vectors WHERE vine_id = ?", (vine_id,)
            )
            self._connection.execute(
                "DELETE FROM memory_terms WHERE vine_id = ?", (vine_id,)
            )
            for ordinal, vector in enumerate(vectors):
                clean = _normalize_embedding_vector(vector)
                nonce = os.urandom(AES_GCM_NONCE_BYTES)
                ciphertext = AESGCM(key).encrypt(
                    nonce,
                    clean.astype(np.float64, copy=False).tobytes(order="C"),
                    scoped_aad(
                        object_type="retrieval-vector",
                        scope_id=keyring.scope_id,
                        record_id=vine_id,
                        schema_version=PAYLOAD_SCHEMA_VERSION,
                        key_id=key_id,
                        ordinal=ordinal,
                        dimension=int(clean.size),
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO memory_vectors(
                        vine_id, ordinal, nonce, ciphertext, dimension,
                        key_id, scope_id, format_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        vine_id,
                        ordinal,
                        nonce,
                        ciphertext,
                        clean.size,
                        key_id,
                        keyring.scope_id,
                        PAYLOAD_SCHEMA_VERSION,
                    ),
                )
            self._connection.executemany(
                """
                INSERT INTO memory_terms(
                    vine_id, term_hash, term_count, key_id
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (vine_id, term_hash, count, key_id)
                    for term_hash, count in terms.items()
                ],
            )
            self._refresh_record_integrity(vine_id)
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def _lexical_matches(self, query: str) -> dict[str, tuple[float, int]]:
        if not self._secure_schema:
            return super()._lexical_matches(query)
        keyring = self._require_keyring()
        query_terms_by_key: dict[str, dict[bytes, int]] = {
            key_id: self._term_features_for_key(
                query,
                MAX_QUERY_FEATURES,
                keyring.key(key_id),
            )
            for key_id in keyring.key_ids
        }
        flattened: dict[bytes, tuple[str, int]] = {}
        for key_id, terms in query_terms_by_key.items():
            for term_hash, count in terms.items():
                flattened[term_hash] = (key_id, count)
        if not flattened:
            return {}
        placeholders = ",".join("?" for _ in flattened)
        term_query = (
            "SELECT memory_terms.vine_id, memory_terms.term_hash, "
            "memory_terms.term_count, memory_terms.key_id "
            "FROM memory_terms "
            "JOIN payloads ON payloads.vine_id = memory_terms.vine_id "
            "LEFT JOIN quarantine ON quarantine.vine_id = memory_terms.vine_id "
            f"WHERE memory_terms.term_hash IN ({placeholders}) "
            "AND payloads.operation_state = 'committed' "
            "AND quarantine.vine_id IS NULL"
        )
        rows = self._connection.execute(term_query, tuple(flattened)).fetchall()
        matched_counts: dict[str, int] = {}
        matched_unique: dict[str, int] = {}
        query_count_by_key = {
            key_id: sum(terms.values()) for key_id, terms in query_terms_by_key.items()
        }
        query_unique_by_key = {
            key_id: len(terms) for key_id, terms in query_terms_by_key.items()
        }
        candidate_key: dict[str, str] = {}
        authenticated: dict[str, bool] = {}
        for vine_id_raw, term_hash_raw, count_raw, key_id_raw in rows:
            vine_id = str(vine_id_raw)
            if vine_id not in authenticated:
                try:
                    self._verify_record_integrity(vine_id)
                except QuarantinedRecordError:
                    authenticated[vine_id] = False
                else:
                    authenticated[vine_id] = True
            if not authenticated[vine_id]:
                continue
            key_id = str(key_id_raw)
            term_hash = bytes(term_hash_raw)
            expected = flattened.get(term_hash)
            if expected is None or expected[0] != key_id:
                continue
            candidate_key[vine_id] = key_id
            matched_counts[vine_id] = matched_counts.get(vine_id, 0) + min(
                expected[1],
                int(count_raw),
            )
            matched_unique[vine_id] = matched_unique.get(vine_id, 0) + 1
        return {
            vine_id: (
                min(
                    1.0,
                    0.7
                    * (
                        matched_counts[vine_id]
                        / max(1, query_count_by_key[candidate_key[vine_id]])
                    )
                    + 0.3
                    * (
                        matched_unique[vine_id]
                        / max(1, query_unique_by_key[candidate_key[vine_id]])
                    ),
                ),
                matched_unique[vine_id],
            )
            for vine_id in matched_counts
        }

    def availability_candidates(
        self,
        query: str,
        *,
        as_of: float | None,
    ) -> list[_AvailabilityCandidate]:
        if not self._secure_schema:
            return super().availability_candidates(query, as_of=as_of)
        broad = self._lexical_matches(query)
        predicate = self._lexical_matches(_predicate_query(query))
        if not predicate:
            return []
        candidate_ids = sorted(
            predicate,
            key=lambda vine_id: (
                predicate[vine_id][0],
                predicate[vine_id][1],
                vine_id,
            ),
            reverse=True,
        )[:MAX_RETRIEVAL_CANDIDATES]
        placeholders = ",".join("?" for _ in candidate_ids)
        candidate_query = (
            "SELECT payloads.vine_id, payloads.topic, payloads.effective_at, "
            "payloads.superseded_by, payloads.superseded_at "
            "FROM payloads "
            "LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id "
            f"WHERE payloads.vine_id IN ({placeholders}) "
            "AND payloads.operation_state = 'committed' "
            "AND quarantine.vine_id IS NULL"
        )
        rows = self._connection.execute(
            candidate_query,
            tuple(candidate_ids),
        ).fetchall()
        candidates: list[_AvailabilityCandidate] = []
        for row in rows:
            vine_id = str(row[0])
            effective_at = _validate_stored_timestamp(row[2], "effective_at")
            superseded_at = (
                None
                if row[4] is None
                else _validate_stored_timestamp(row[4], "superseded_at")
            )
            if as_of is not None and effective_at > as_of:
                continue
            temporal_current = row[3] is None
            if as_of is not None:
                temporal_current = superseded_at is None or as_of < superseded_at
                if not temporal_current:
                    continue
            predicate_score, matched_features = predicate[vine_id]
            lexical_score = broad.get(vine_id, (0.0, 0))[0]
            score = min(1.0, 0.85 * predicate_score + 0.15 * lexical_score)
            candidates.append(
                _AvailabilityCandidate(
                    vine_id=vine_id,
                    topic=_validate_stored_topic(row[1]),
                    score=score,
                    lexical_score=lexical_score,
                    predicate_score=predicate_score,
                    matched_features=matched_features,
                    effective_at=effective_at,
                    superseded_by=None if row[3] is None else str(row[3]),
                    superseded_at=superseded_at,
                    temporal_current=temporal_current,
                )
            )
        return sorted(
            candidates,
            key=lambda item: (
                1 if item.temporal_current else 0,
                item.score,
                item.effective_at,
                item.vine_id,
            ),
            reverse=True,
        )

    def list_records(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 1000
        ):
            raise ValueError("record listing limit must be between 1 and 1000")
        if not self._secure_schema:
            rows = self._connection.execute(
                """
                SELECT vine_id, topic, effective_at, superseded_by, superseded_at
                FROM payloads
                ORDER BY created_at, vine_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            records: list[dict[str, Any]] = []
            for row in rows:
                payload = super().get(str(row[0]))
                if payload is None:
                    continue
                records.append(
                    {
                        "vine_id": str(row[0]),
                        "topic": _validate_stored_topic(row[1]),
                        "payload": payload,
                        "effective_at": _validate_stored_timestamp(
                            row[2],
                            "effective_at",
                        ),
                        "superseded_by": (None if row[3] is None else str(row[3])),
                        "superseded_at": (
                            None
                            if row[4] is None
                            else _validate_stored_timestamp(
                                row[4],
                                "superseded_at",
                            )
                        ),
                    }
                )
            return records
        rows = self._connection.execute(
            """
            SELECT payloads.vine_id, payloads.effective_at,
                   payloads.superseded_by, payloads.superseded_at
            FROM payloads
            LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id
            WHERE payloads.operation_state = 'committed'
              AND quarantine.vine_id IS NULL
            ORDER BY payloads.created_at, payloads.vine_id
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        records = []
        for row in rows:
            vine_id = str(row[0])
            try:
                record = self.get_record(vine_id)
            except QuarantinedRecordError:
                continue
            if record is None:
                continue
            records.append(
                {
                    "vine_id": vine_id,
                    "topic": record[0],
                    "payload": record[1],
                    "effective_at": _validate_stored_timestamp(
                        row[1],
                        "effective_at",
                    ),
                    "superseded_by": None if row[2] is None else str(row[2]),
                    "superseded_at": (
                        None
                        if row[3] is None
                        else _validate_stored_timestamp(row[3], "superseded_at")
                    ),
                }
            )
        return records

    def quarantine_count(self) -> int:
        if not self._secure_schema:
            return 0
        row = self._connection.execute("SELECT COUNT(*) FROM quarantine").fetchone()
        return 0 if row is None else int(row[0])

    def tombstone_count(self) -> int:
        if not self._secure_schema:
            return 0
        return self._verify_tombstones()

    def key_usage(self, key_id: str) -> int:
        if not self._secure_schema:
            return 0
        queries = (
            "SELECT COUNT(*) FROM payloads WHERE key_id = ?",
            "SELECT COUNT(*) FROM memory_vectors WHERE key_id = ?",
            "SELECT COUNT(*) FROM memory_terms WHERE key_id = ?",
            "SELECT COUNT(*) FROM deletion_tombstones WHERE key_id = ?",
        )
        counts = [
            self._connection.execute(query, (key_id,)).fetchone() for query in queries
        ]
        total = sum(0 if row is None else int(row[0]) for row in counts)
        contract_rows = self._connection.execute(
            """
            SELECT value FROM adapter_metadata
            WHERE key LIKE 'memory_contract:%'
            """
        ).fetchall()
        for row in contract_rows:
            try:
                protected = ScopedProtectedBlob.from_json_bytes(
                    str(row[0]).encode("ascii")
                )
            except Exception as exc:
                raise RuntimeError("protected memory contract is corrupt") from exc
            if protected.key_id == key_id:
                total += 1
        return total

    def rotate_batch(
        self,
        *,
        source_key_id: str,
        target_key_id: str,
        limit: int,
    ) -> dict[str, int]:
        if not self._secure_schema:
            raise RuntimeError("legacy profiles must migrate to a scoped-v2 profile")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 1000
        ):
            raise ValueError("rotation batch limit must be between 1 and 1000")
        self._verify_tombstones()
        rows = self._connection.execute(
            """
            SELECT payloads.vine_id
            FROM payloads
            LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id
            WHERE payloads.key_id = ?
              AND payloads.operation_state = 'committed'
              AND quarantine.vine_id IS NULL
            ORDER BY payloads.created_at, payloads.vine_id
            LIMIT ?
            """,
            (source_key_id, limit),
        ).fetchall()
        migrated = 0
        failed = 0
        for row in rows:
            try:
                self._reencrypt_record(str(row[0]), target_key_id)
            except (QuarantinedRecordError, KeyUnavailable):
                failed += 1
            else:
                migrated += 1
        remaining_limit = max(0, limit - migrated - failed)
        tombstones = 0
        if remaining_limit:
            tombstones = self._rotate_tombstones(
                source_key_id,
                target_key_id,
                remaining_limit,
            )
        return {
            "migrated_records": migrated,
            "migrated_tombstones": tombstones,
            "failed_records": failed,
            "remaining_key_references": self.key_usage(source_key_id),
        }

    def __len__(self) -> int:
        if not self._secure_schema:
            return super().__len__()
        row = self._connection.execute(
            """
            SELECT COUNT(*)
            FROM payloads
            LEFT JOIN quarantine ON quarantine.vine_id = payloads.vine_id
            WHERE payloads.operation_state = 'committed'
              AND quarantine.vine_id IS NULL
            """
        ).fetchone()
        return 0 if row is None else int(row[0])

    def _decrypt_record(
        self,
        vine_id: str,
        row: tuple[Any, ...],
    ) -> tuple[str, str]:
        keyring = self._require_keyring()
        nonce = bytes(row[0])
        ciphertext = bytes(row[1])
        key_id = str(row[2])
        scope_id = str(row[3])
        format_version = int(row[4])
        if (
            len(nonce) != AES_GCM_NONCE_BYTES
            or not 16
            < len(ciphertext)
            <= (MAX_PAYLOAD_CHARS + MAX_TOPIC_CHARS) * 4 + 4096
            or scope_id != keyring.scope_id
            or format_version != PAYLOAD_SCHEMA_VERSION
        ):
            self._quarantine(vine_id, "payload_metadata")
            raise QuarantinedRecordError("encrypted record is quarantined")
        try:
            plaintext = bytearray(
                AESGCM(keyring.key(key_id)).decrypt(
                    nonce,
                    ciphertext,
                    scoped_aad(
                        object_type="payload",
                        scope_id=scope_id,
                        record_id=vine_id,
                        schema_version=format_version,
                        key_id=key_id,
                    ),
                )
            )
        except (InvalidTag, KeyUnavailable) as exc:
            self._quarantine(vine_id, "payload_authentication")
            raise QuarantinedRecordError("encrypted record is quarantined") from exc
        try:
            decoded = strict_json_loads(bytes(plaintext))
            if not isinstance(decoded, dict) or set(decoded) != {
                "key_id",
                "payload",
                "record_id",
                "schema_version",
                "scope_id",
                "topic",
            }:
                raise ValueError
            if (
                decoded["key_id"] != key_id
                or decoded["record_id"] != vine_id
                or decoded["schema_version"] != format_version
                or decoded["scope_id"] != scope_id
            ):
                raise ValueError
            topic = _validate_stored_topic(decoded["topic"])
            payload = _validate_text(
                decoded["payload"],
                "stored payload",
                MAX_PAYLOAD_CHARS,
            )
            return topic, payload
        except Exception as exc:
            self._quarantine(vine_id, "payload_envelope")
            raise QuarantinedRecordError("encrypted record is quarantined") from exc
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0

    def _decrypt_vector(
        self,
        *,
        vine_id: str,
        ordinal: int,
        nonce: bytes,
        ciphertext: bytes,
        dimension: int,
        key_id: str,
        scope_id: str,
        format_version: int,
    ) -> NDArray[np.float64]:
        keyring = self._require_keyring()
        if (
            ordinal < 0
            or ordinal >= MAX_MEMORY_PASSAGES
            or dimension <= 0
            or dimension > 65_536
            or len(nonce) != AES_GCM_NONCE_BYTES
            or len(ciphertext) != dimension * 8 + 16
            or scope_id != keyring.scope_id
            or format_version != PAYLOAD_SCHEMA_VERSION
        ):
            raise QuarantinedRecordError("retrieval vector is quarantined")
        plaintext = bytearray()
        try:
            plaintext = bytearray(
                AESGCM(keyring.key(key_id)).decrypt(
                    nonce,
                    ciphertext,
                    scoped_aad(
                        object_type="retrieval-vector",
                        scope_id=scope_id,
                        record_id=vine_id,
                        schema_version=format_version,
                        key_id=key_id,
                        ordinal=ordinal,
                        dimension=dimension,
                    ),
                )
            )
            expected = dimension * np.dtype(np.float64).itemsize
            if len(plaintext) != expected:
                raise QuarantinedRecordError("retrieval vector is quarantined")
            return _normalize_embedding_vector(
                np.frombuffer(plaintext, dtype=np.float64).copy(),
                expected_dimension=dimension,
                source="stored retrieval vector",
            )
        except (InvalidTag, KeyUnavailable) as exc:
            raise QuarantinedRecordError("retrieval vector is quarantined") from exc
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0

    def _quarantine(self, vine_id: str, reason_code: str) -> None:
        if not self._secure_schema or self._read_only:
            return
        safe_reason = (
            reason_code
            if re.fullmatch(r"[a-z0-9_]{1,64}", reason_code)
            else "authentication_failure"
        )
        self._connection.execute(
            """
            INSERT INTO quarantine(vine_id, reason_code, detected_at)
            VALUES (?, ?, ?)
            ON CONFLICT(vine_id) DO NOTHING
            """,
            (vine_id, safe_reason, time.time()),
        )

    def _reencrypt_record(self, vine_id: str, target_key_id: str) -> None:
        keyring = self._require_keyring()
        self._verify_record_integrity(vine_id)
        row = self._connection.execute(
            """
            SELECT CAST(nonce AS BLOB), CAST(ciphertext AS BLOB),
                   key_id, scope_id, format_version
            FROM payloads
            WHERE vine_id = ? AND operation_state = 'committed'
            """,
            (vine_id,),
        ).fetchone()
        if row is None:
            return
        topic, payload = self._decrypt_record(vine_id, row)
        contract = self.get_memory_contract(vine_id)
        contract_value = self._encode_memory_contract(vine_id, contract)
        protected_contract = ScopedProtectedBlob.from_json_bytes(
            contract_value.encode("ascii")
        )
        if protected_contract.key_id != target_key_id:
            raise RuntimeError("memory contract rotation target is inconsistent")
        vector_rows = self._connection.execute(
            """
            SELECT ordinal, CAST(nonce AS BLOB), CAST(ciphertext AS BLOB),
                   dimension, key_id, scope_id, format_version
            FROM memory_vectors
            WHERE vine_id = ?
            ORDER BY ordinal
            """,
            (vine_id,),
        ).fetchall()
        vectors: list[tuple[int, NDArray[np.float64]]] = []
        try:
            for vector_row in vector_rows:
                ordinal = int(vector_row[0])
                vectors.append(
                    (
                        ordinal,
                        self._decrypt_vector(
                            vine_id=vine_id,
                            ordinal=ordinal,
                            nonce=bytes(vector_row[1]),
                            ciphertext=bytes(vector_row[2]),
                            dimension=int(vector_row[3]),
                            key_id=str(vector_row[4]),
                            scope_id=str(vector_row[5]),
                            format_version=int(vector_row[6]),
                        ),
                    )
                )
            target_key = keyring.key(target_key_id)
            scope_id = keyring.scope_id
            payload_nonce = os.urandom(AES_GCM_NONCE_BYTES)
            envelope = self._encode_envelope(
                vine_id=vine_id,
                topic=topic,
                payload=payload,
                key_id=target_key_id,
                scope_id=scope_id,
            )
            payload_ciphertext = AESGCM(target_key).encrypt(
                payload_nonce,
                envelope,
                scoped_aad(
                    object_type="payload",
                    scope_id=scope_id,
                    record_id=vine_id,
                    schema_version=PAYLOAD_SCHEMA_VERSION,
                    key_id=target_key_id,
                ),
            )
            encrypted_vectors: list[tuple[int, bytes, bytes, int]] = []
            for ordinal, vector in vectors:
                nonce = os.urandom(AES_GCM_NONCE_BYTES)
                encrypted_vectors.append(
                    (
                        ordinal,
                        nonce,
                        AESGCM(target_key).encrypt(
                            nonce,
                            vector.astype(np.float64, copy=False).tobytes(order="C"),
                            scoped_aad(
                                object_type="retrieval-vector",
                                scope_id=scope_id,
                                record_id=vine_id,
                                schema_version=PAYLOAD_SCHEMA_VERSION,
                                key_id=target_key_id,
                                ordinal=ordinal,
                                dimension=int(vector.size),
                            ),
                        ),
                        int(vector.size),
                    )
                )
            terms = self._term_features_for_key(
                f"{topic}\n{payload}",
                MAX_LEXICAL_FEATURES,
                target_key,
            )
            content_hash = self._content_digest(target_key, topic, payload)
            topic_value = opaque_topic(target_key, scope_id, topic)
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    """
                    UPDATE payloads
                    SET topic = ?, nonce = ?, ciphertext = ?, key_id = ?,
                        scope_id = ?, format_version = ?, content_hash = ?
                    WHERE vine_id = ?
                    """,
                    (
                        topic_value,
                        payload_nonce,
                        payload_ciphertext,
                        target_key_id,
                        scope_id,
                        PAYLOAD_SCHEMA_VERSION,
                        content_hash,
                        vine_id,
                    ),
                )
                self._connection.execute(
                    "DELETE FROM memory_vectors WHERE vine_id = ?", (vine_id,)
                )
                self._connection.executemany(
                    """
                    INSERT INTO memory_vectors(
                        vine_id, ordinal, nonce, ciphertext, dimension,
                        key_id, scope_id, format_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            vine_id,
                            ordinal,
                            nonce,
                            ciphertext,
                            dimension,
                            target_key_id,
                            scope_id,
                            PAYLOAD_SCHEMA_VERSION,
                        )
                        for ordinal, nonce, ciphertext, dimension in encrypted_vectors
                    ],
                )
                self._connection.execute(
                    "DELETE FROM memory_terms WHERE vine_id = ?", (vine_id,)
                )
                self._connection.executemany(
                    """
                    INSERT INTO memory_terms(
                        vine_id, term_hash, term_count, key_id
                    ) VALUES (?, ?, ?, ?)
                    """,
                    [
                        (vine_id, term_hash, count, target_key_id)
                        for term_hash, count in terms.items()
                    ],
                )
                self._connection.execute(
                    """
                    UPDATE adapter_metadata
                    SET value = ?
                    WHERE key = ?
                    """,
                    (contract_value, _memory_contract_key(vine_id)),
                )
                self._refresh_record_integrity(vine_id)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        except (QuarantinedRecordError, KeyUnavailable):
            self._quarantine(vine_id, "rotation_authentication")
            raise
        finally:
            for _ordinal, vector in vectors:
                vector.fill(0.0)
            payload = ""
            topic = ""

    def _rotate_tombstones(
        self,
        source_key_id: str,
        target_key_id: str,
        limit: int,
    ) -> int:
        keyring = self._require_keyring()
        target_key = keyring.key(target_key_id)
        rows = self._connection.execute(
            """
            SELECT vine_id, deleted_at, scope_id, CAST(auth_tag AS BLOB)
            FROM deletion_tombstones
            WHERE key_id = ?
            ORDER BY deleted_at, vine_id
            LIMIT ?
            """,
            (source_key_id, limit),
        ).fetchall()
        migrated = 0
        for vine_id_raw, deleted_at_raw, scope_id_raw, tag_raw in rows:
            vine_id = str(vine_id_raw)
            deleted_at = float(deleted_at_raw)
            scope_id = str(scope_id_raw)
            expected = self._tombstone_tag(
                keyring.key(source_key_id),
                vine_id,
                deleted_at,
                scope_id,
                source_key_id,
            )
            if not hmac.compare_digest(expected, bytes(tag_raw)):
                raise RuntimeError("authenticated deletion state is corrupt")
            tag = self._tombstone_tag(
                target_key,
                vine_id,
                deleted_at,
                scope_id,
                target_key_id,
            )
            self._connection.execute(
                """
                UPDATE deletion_tombstones
                SET key_id = ?, auth_tag = ?
                WHERE vine_id = ? AND key_id = ?
                """,
                (target_key_id, tag, vine_id, source_key_id),
            )
            migrated += 1
        return migrated

    def _require_keyring(self) -> ProfileKeyring:
        if self._keyring is None:
            raise KeyUnavailable("secure profile keyring is unavailable")
        return self._keyring

    @staticmethod
    def _content_digest(key: bytes, topic: str, payload: str) -> str:
        digest = hashlib.blake2b(
            key=key,
            digest_size=32,
            person=b"echo-v-dedupe-v2",
        )
        digest.update(topic.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload.encode("utf-8"))
        return digest.hexdigest()

    @staticmethod
    def _term_features_for_key(
        text: str,
        limit: int,
        key: bytes,
    ) -> dict[bytes, int]:
        raw = _lexical_features(text, limit)
        return {
            hashlib.blake2b(
                feature.encode("utf-8"),
                key=key,
                digest_size=16,
                person=b"echo-v-term-v2",
            ).digest(): count
            for feature, count in raw.items()
        }

    @staticmethod
    def _encode_envelope(
        *,
        vine_id: str,
        topic: str,
        payload: str,
        key_id: str,
        scope_id: str,
    ) -> bytes:
        return json.dumps(
            {
                "key_id": key_id,
                "payload": payload,
                "record_id": vine_id,
                "schema_version": PAYLOAD_SCHEMA_VERSION,
                "scope_id": scope_id,
                "topic": topic,
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _tombstone_tag(
        key: bytes,
        vine_id: str,
        deleted_at: float,
        scope_id: str,
        key_id: str,
    ) -> bytes:
        message = json.dumps(
            {
                "deleted_at": deleted_at,
                "key_id": key_id,
                "record_id": vine_id,
                "schema_version": PAYLOAD_SCHEMA_VERSION,
                "scope_id": scope_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(
            key,
            b"echo-veil-tombstone-v2\0" + message,
            hashlib.sha256,
        ).digest()


class AgentMemory:
    """Concrete Echo Veil memory adapter for a single local host profile."""

    def __init__(
        self,
        state_dir: str | os.PathLike[str] | None = None,
        *,
        profile: str = "default",
        scope: str = "local-user",
        capacity: int = DEFAULT_CAPACITY,
        embed: TextEmbedder | Callable[[str], NDArray[np.float64]] | None = None,
        embedder_id: str | None = None,
        profile_lock_timeout_seconds: float = DEFAULT_PROFILE_LOCK_TIMEOUT_SECONDS,
        deployment_mode: str = LOCAL_STAGING_MODE,
    ) -> None:
        profile_name = _validate_profile(profile)
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("capacity must be a positive integer")
        if capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        if deployment_mode not in {LOCAL_STAGING_MODE, LOCAL_PRODUCTION_MODE}:
            raise ValueError(
                "deployment_mode must be local-staging or local-production"
            )

        base = (
            default_state_dir() if state_dir is None else Path(state_dir).expanduser()
        )
        self.profile_dir = _secure_directory(base / profile_name)
        self._embedder = _coerce_embedder(embed, embedder_id)
        self._deployment_mode = deployment_mode
        # Positive evidence is populated only by reviewed custody, artifact,
        # recovery, and host-boundary verifiers.  RPC input and environment
        # variables must never be able to self-assert these fields.
        self._readiness_evidence = LocalReadinessEvidence()
        self._lease = _ProfileWriterLease(
            self.profile_dir / "profile-lock.db",
            profile_lock_timeout_seconds,
        )
        self._closed = False
        self._recovered_lifecycle_orphans = 0
        self._migrated_memory_contracts = 0
        self._authenticated_record_migrations = 0
        self._expired_live_pruned = 0
        self._restored_on_startup = False
        self._store: SQLiteStore | None = None
        self._keyring: ProfileKeyring | None = None
        self._scoped_shield: ScopedAesGcmShield | None = None
        try:
            payload_path = self.profile_dir / "payloads.db"
            payload_version = _payload_database_version(payload_path)
            if payload_version == LEGACY_PAYLOAD_SCHEMA_VERSION:
                key = _load_existing_key(self.profile_dir / "agent.key")
                self._payloads = _EncryptedPayloadStore(
                    payload_path,
                    legacy_key=key,
                )
                shield: AesGcmCryptoShield | ScopedAesGcmShield = AesGcmCryptoShield(
                    key
                )
                self._store = SQLiteStore(self.profile_dir / "echo-veil.db")
            else:
                self._keyring = ProfileKeyring(self.profile_dir, scope)
                self._payloads = _EncryptedPayloadStore(
                    payload_path,
                    keyring=self._keyring,
                )
                self._scoped_shield = ScopedAesGcmShield(self._keyring)
                shield = self._scoped_shield
                self._store = SQLiteStore(
                    self.profile_dir / "echo-veil.db",
                    protected_payload_loader=ScopedProtectedVector.from_json_bytes,
                )
            self.oracle = Oracle(
                WorkspaceConfig(capacity=capacity),
                shield=shield,
                environment="staging",
                storage=cast(TransactionalEvictionStore, self._store),
            )
            self._recovered_lifecycle_orphans = self._recover_incomplete_operations()
            self._bind_embedding_identity()
            self._migrated_memory_contracts = (
                self._payloads.initialize_memory_contracts()
            )
            self._authenticated_record_migrations = (
                self._payloads.initialize_record_integrity()
            )
            if self._payloads.metadata_protected:
                # Provision the per-profile turn-receipt key during adapter
                # startup so every later preflight remains read-only.
                from .preflight_receipt import PreflightReceiptAuthority

                PreflightReceiptAuthority(self.profile_dir, create=True)
            self._expired_live_pruned = self._prune_expired_live_memory()
            self._restored_on_startup = True
        except Exception:
            payloads = getattr(self, "_payloads", None)
            try:
                if payloads is not None:
                    payloads.close()
            finally:
                try:
                    if self._store is not None:
                        self._store.close()
                finally:
                    self._lease.close()
                    self._closed = True
            raise

    @property
    def scope(self) -> str:
        """Return the authenticated logical authorization scope."""

        if self._keyring is None:
            raise RuntimeError("legacy profiles do not expose a protected scope")
        return self._keyring.scope

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
        if not self._payloads.metadata_protected:
            raise RuntimeError(
                "legacy profiles are migration-only; fully shielded memory "
                "requires a scoped-v2 profile"
            )
        clean_topic = _validate_text(topic, "topic", MAX_TOPIC_CHARS)
        clean_payload = _validate_text(payload, "payload", MAX_PAYLOAD_CHARS)
        effective = _validate_timestamp(effective_at, "effective_at")
        superseded_ids = _validate_vine_ids(supersedes)
        contract = new_memory_contract(
            layer,
            provenance=provenance,
            promotion_reason=promotion_reason,
            expires_at=expires_at,
            logic_kind=logic_kind,
            related_ids=related_ids,
        )

        _validate_memory_content_policy(
            contract.layer,
            clean_payload,
            operation="memory write",
        )
        if contract.layer == MemoryLayer.CONTEXTUAL_LOGIC:
            self._prune_expired_live_memory()
            missing_related = [
                vine_id
                for vine_id in contract.related_ids
                if not self._managed_exists(vine_id)
            ]
            if missing_related:
                raise ValueError("contextual-logic memory references an unknown memory")
        content_hash = self._payloads.digest(clean_topic, clean_payload)
        existing = self._payloads.find_duplicate(clean_topic, clean_payload)
        if existing is not None and self._managed_exists(existing[0]):
            existing_contract = self._payloads.get_memory_contract(existing[0])
            return {
                "vine_id": existing[0],
                "topic": existing[1],
                "created": False,
                "duplicate": True,
                **_public_record_contract(existing_contract, clean_payload),
            }
        if existing is not None:
            self._payloads.delete(existing[0], tombstone=False)

        passages = _memory_passages(clean_topic, clean_payload)
        vectors = _embed_document_batch(self._embedder, passages)
        primary = _normalize_embedding_vector(np.mean(np.stack(vectors), axis=0))
        vine_id = uuid.uuid4().hex
        self._payloads.put(
            vine_id,
            clean_topic,
            clean_payload,
            content_hash,
            vectors=vectors,
            effective_at=effective,
            supersedes=superseded_ids,
            contract=contract,
        )
        try:
            vine = self.oracle.sprout(
                self._payloads.topic_token(clean_topic),
                primary,
                vine_id=vine_id,
            )
            self._payloads.mark_committed(vine_id)
        except Exception:
            self.oracle.forget(vine_id)
            self._payloads.delete(vine_id, tombstone=False)
            raise
        return {
            "vine_id": vine.vine_id,
            "topic": clean_topic,
            "created": True,
            "duplicate": False,
            "effective_at": effective,
            "supersedes": list(superseded_ids),
            **_public_record_contract(contract, clean_payload),
        }

    def refresh_live(
        self,
        vine_id: str,
        payload: str,
        *,
        provenance: list[str] | tuple[str, ...] | None = None,
        expires_at: float | None = None,
    ) -> dict[str, Any]:
        """Refresh Live state, preserving changed content as supersession history."""

        if not self._payloads.metadata_protected:
            raise RuntimeError(
                "legacy profiles are migration-only; protected Live refresh "
                "requires a scoped-v2 profile"
            )
        clean_id = _validate_text(vine_id, "vine_id", 128)
        clean_payload = _validate_text(payload, "payload", MAX_PAYLOAD_CHARS)
        self._prune_expired_live_memory()
        if not self._managed_exists(clean_id):
            raise KeyError("live memory does not exist or has expired")
        current = self._payloads.get_memory_contract(clean_id)
        if current.layer != MemoryLayer.LIVE:
            raise ValueError("only live memory can be refreshed")
        details = self._payloads.get_record_details(clean_id)
        if details is None:
            raise KeyError("live memory does not exist")
        if details["superseded_by"] is not None:
            raise ValueError("superseded live memory cannot be refreshed")
        refreshed_contract = current.refresh_live(
            provenance=provenance,
            expires_at=expires_at,
        )
        _validate_memory_content_policy(
            MemoryLayer.LIVE,
            clean_payload,
            operation="live memory refresh",
        )
        prior_payload = str(details["payload"])
        if hmac.compare_digest(
            clean_payload.encode("utf-8"),
            prior_payload.encode("utf-8"),
        ):
            self._payloads.set_memory_contract(clean_id, refreshed_contract)
            return {
                "vine_id": clean_id,
                "previous_vine_id": clean_id,
                "topic": str(details["topic"]),
                "created": False,
                "duplicate": False,
                "refreshed": True,
                "content_changed": False,
                "effective_at": float(details["effective_at"]),
                "supersedes": [],
                **_public_record_contract(refreshed_contract, clean_payload),
            }

        refreshed = self.remember(
            str(details["topic"]),
            clean_payload,
            supersedes=[clean_id],
            layer=MemoryLayer.LIVE,
            provenance=list(refreshed_contract.provenance),
            expires_at=refreshed_contract.expires_at,
        )
        return {
            **refreshed,
            "previous_vine_id": clean_id,
            "refreshed": True,
            "content_changed": True,
        }

    def promote(
        self,
        vine_id: str,
        target_layer: MemoryLayer | str,
        *,
        reason: str,
        provenance: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        """Deliberately promote live→short-term or short-term→long-term."""

        if not self._payloads.metadata_protected:
            raise RuntimeError(
                "legacy profiles are migration-only; protected promotion is unavailable"
            )
        clean_id = _validate_text(vine_id, "vine_id", 128)
        if not self._managed_exists(clean_id):
            raise KeyError("memory does not exist")
        current = self._payloads.get_memory_contract(clean_id)
        promoted = current.promote(
            target_layer,
            reason=reason,
            provenance=provenance,
        )
        record = self._payloads.get_record(clean_id)
        if record is None:
            raise KeyError("memory does not exist")
        _validate_memory_content_policy(
            promoted.layer,
            record[1],
            operation=(f"{current.layer.value} to {promoted.layer.value} promotion"),
        )
        self._payloads.set_memory_contract(clean_id, promoted)
        return {
            "vine_id": clean_id,
            "promoted": True,
            "previous_layer": current.layer.value,
            **_public_record_contract(promoted, record[1]),
        }

    def recall(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float | None = None,
        allow_inferential: bool = False,
        as_of: float | None = None,
        layers: list[str] | tuple[str, ...] | None = None,
        mutate_lifecycle: bool = False,
    ) -> dict[str, Any]:
        """Return semantic recall. Ordinary calls are lifecycle-neutral."""

        return self._recall(
            query,
            top_k=top_k,
            min_score=min_score,
            allow_inferential=allow_inferential,
            as_of=as_of,
            layers=layers,
            mutate_lifecycle=mutate_lifecycle,
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
        """Return semantic recall without pruning, observation, or reinforcement."""

        return self._recall(
            query,
            top_k=top_k,
            min_score=min_score,
            allow_inferential=allow_inferential,
            as_of=as_of,
            layers=layers,
            mutate_lifecycle=False,
        )

    def _recall(
        self,
        query: str,
        *,
        top_k: int,
        min_score: float | None,
        allow_inferential: bool,
        as_of: float | None,
        layers: list[str] | tuple[str, ...] | None,
        mutate_lifecycle: bool,
    ) -> dict[str, Any]:
        if not self._payloads.metadata_protected:
            raise RuntimeError(
                "legacy profiles are migration-only; fully shielded recall "
                "requires a scoped-v2 profile"
            )
        clean_query = _validate_text(query, "query", MAX_QUERY_CHARS)
        expired_live_pruned = (
            self._prune_expired_live_memory() if mutate_lifecycle else 0
        )
        if isinstance(top_k, bool) or not isinstance(top_k, int):
            raise TypeError("top_k must be an integer")
        if not 1 <= top_k <= MAX_RECALL_RESULTS:
            raise ValueError(f"top_k must be between 1 and {MAX_RECALL_RESULTS}")
        if min_score is None:
            threshold = self._embedder.default_min_score
        elif isinstance(min_score, bool) or not isinstance(min_score, (int, float)):
            raise TypeError("min_score must be a finite number or None")
        else:
            threshold = float(min_score)
        if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise ValueError("min_score must be between 0 and 1")
        if not isinstance(allow_inferential, bool):
            raise TypeError("allow_inferential must be a bool")
        point_in_time = _validate_optional_timestamp(as_of, "as_of")
        requested_layers = _validate_memory_layers(layers)

        retrieval_query_embed = getattr(self._embedder, "embed_retrieval_queries", None)
        answerability_embed = getattr(self._embedder, "embed_answerability_query", None)
        if self._embedder.semantic and callable(retrieval_query_embed):
            intent, answerability_intent = retrieval_query_embed(clean_query)
        else:
            intent = self._embedder.embed_query(clean_query)
            answerability_intent = (
                answerability_embed(clean_query)
                if self._embedder.semantic and callable(answerability_embed)
                else None
            )
        answerability_threshold = (
            DEFAULT_ANSWERABILITY_MIN_SCORE
            if answerability_intent is not None
            else None
        )
        lifecycle = (
            self.oracle.observe(intent)
            if mutate_lifecycle
            else {"mode": "read-only-preview", "mutated": False}
        )
        active = {vine.vine_id: vine for vine in self.oracle.workspace.active()}
        cold_limit = min(MAX_RECALL_RESULTS * 3, max(top_k * 3, 10))
        cold_scores = dict(self.oracle.search_index(intent, top_k=cold_limit))
        semantic_candidates = [
            vine.vine_id
            for vine in sorted(
                active.values(),
                key=lambda candidate: candidate.score,
                reverse=True,
            )
        ]
        semantic_candidates.extend(
            vine_id
            for vine_id, _score in sorted(
                cold_scores.items(),
                key=lambda item: item[1],
                reverse=True,
            )
        )
        stored = self._payloads.retrieval_candidates(
            intent,
            clean_query,
            semantic_candidates,
            answerability_intent,
        )
        candidates: list[_RankedCandidate] = []
        contracts: dict[str, MemoryLayerContract] = {}
        answerability_rejected_count = 0
        for vine_id, item in stored.items():
            if point_in_time is not None and item.effective_at > point_in_time:
                continue
            temporal_current = item.superseded_by is None
            if point_in_time is not None:
                temporal_current = (
                    item.superseded_at is None or point_in_time < item.superseded_at
                )
                if not temporal_current:
                    continue
            try:
                contract = self._payloads.get_memory_contract(vine_id)
            except QuarantinedRecordError:
                continue
            if contract.is_expired():
                continue
            if requested_layers is not None and contract.layer not in requested_layers:
                continue
            contracts[vine_id] = contract
            vine = active.get(vine_id)
            lifecycle_score: float | None = None
            semantic_score = item.semantic_score
            if vine is not None:
                lifecycle_score = vine.score
                if semantic_score is None:
                    semantic_score = vine.score - time_decay(
                        vine.age_hours(), self.oracle.workspace.config.proximity
                    )
                source = "active"
            elif self.oracle.archived_metadata(vine_id) is not None:
                source = "archive"
                if semantic_score is None:
                    semantic_score = cold_scores.get(vine_id)
            else:
                continue
            base_relevance = _hybrid_relevance(semantic_score, item.lexical_score)
            if base_relevance < threshold:
                continue
            if answerability_threshold is not None and (
                item.answerability_score is None
                or item.answerability_score < answerability_threshold
            ):
                answerability_rejected_count += 1
                continue
            relevance = _answerability_relevance(
                base_relevance,
                item.answerability_score,
            )
            candidates.append(
                _RankedCandidate(
                    vine_id=vine_id,
                    topic=item.topic,
                    source=source,
                    relevance_score=relevance,
                    semantic_score=semantic_score,
                    answerability_score=item.answerability_score,
                    lexical_score=item.lexical_score,
                    lifecycle_score=lifecycle_score,
                    best_vector=item.best_vector,
                    effective_at=item.effective_at,
                    superseded_by=item.superseded_by,
                    superseded_at=item.superseded_at,
                    temporal_current=temporal_current,
                )
            )

        ranked = _prioritize_competing_candidates(_mmr_rank(candidates))

        results: list[dict[str, Any]] = []
        result_candidates: list[_RankedCandidate] = []
        scan_limit = 2 if top_k == 1 else top_k
        for candidate in ranked:
            vine_id = candidate.vine_id
            score = candidate.relevance_score
            policy = classify(score)
            contract = contracts[vine_id]
            contract_fields = _public_contract(contract)
            try:
                record = self._payloads.get_record(vine_id)
            except QuarantinedRecordError:
                continue
            if record is None:
                continue
            try:
                self.oracle.check_generation_gate(score, override=allow_inferential)
            except GenerationGated:
                results.append(
                    {
                        "vine_id": vine_id,
                        "topic": (
                            None
                            if self._payloads.metadata_protected
                            else candidate.topic
                        ),
                        "topic_protected": self._payloads.metadata_protected,
                        "score": round(score, 6),
                        "semantic_score": _round_optional(candidate.semantic_score),
                        "answerability_score": _round_optional(
                            candidate.answerability_score
                        ),
                        "lexical_score": round(candidate.lexical_score, 6),
                        "lifecycle_score": _round_optional(candidate.lifecycle_score),
                        "source": candidate.source,
                        "temporal_status": (
                            "valid_at_as_of"
                            if point_in_time is not None
                            else (
                                "current"
                                if candidate.temporal_current
                                else "superseded"
                            )
                        ),
                        "effective_at": candidate.effective_at,
                        "superseded_by": candidate.superseded_by,
                        "superseded_at": candidate.superseded_at,
                        "confidence_band": policy.band.value,
                        "confidence_indicator": policy.indicator,
                        "gated": True,
                        "payload": None,
                        **contract_fields,
                    }
                )
            else:
                topic, payload = record
                if mutate_lifecycle and candidate.source == "active":
                    self.oracle.reinforce(vine_id)
                results.append(
                    {
                        "vine_id": vine_id,
                        "topic": topic,
                        "topic_protected": self._payloads.metadata_protected,
                        "score": round(score, 6),
                        "semantic_score": _round_optional(candidate.semantic_score),
                        "answerability_score": _round_optional(
                            candidate.answerability_score
                        ),
                        "lexical_score": round(candidate.lexical_score, 6),
                        "lifecycle_score": _round_optional(candidate.lifecycle_score),
                        "source": candidate.source,
                        "temporal_status": (
                            "valid_at_as_of"
                            if point_in_time is not None
                            else (
                                "current"
                                if candidate.temporal_current
                                else "superseded"
                            )
                        ),
                        "effective_at": candidate.effective_at,
                        "superseded_by": candidate.superseded_by,
                        "superseded_at": candidate.superseded_at,
                        "confidence_band": policy.band.value,
                        "confidence_indicator": policy.indicator,
                        "gated": False,
                        "payload": payload,
                        **_public_record_contract(contract, payload),
                    }
                )
            result_candidates.append(candidate)
            if len(results) >= scan_limit:
                break

        competing_pair_auto_expanded = (
            top_k == 1
            and len(result_candidates) >= 2
            and _is_competing_pair(result_candidates[0], result_candidates[1])
        )
        effective_top_k = 2 if competing_pair_auto_expanded else top_k
        if len(results) > effective_top_k:
            del results[effective_top_k:]
            del result_candidates[effective_top_k:]

        for rank, result in enumerate(results, start=1):
            result["rank"] = rank
        competing_groups, competing_groups_omitted = _annotate_competing_memories(
            results,
            result_candidates,
        )
        competing_memory_detected = bool(competing_groups)
        result_topic_tokens = [candidate.topic for candidate in result_candidates]
        result_layers = {
            str(result["memory_layer"])
            for result in results
            if isinstance(result.get("memory_layer"), str)
        }
        gated_count = sum(result.get("gated") is True for result in results)
        ranking_margin = (
            None
            if len(results) < 2
            else round(float(results[0]["score"]) - float(results[1]["score"]), 6)
        )
        ranking_ambiguous = (
            ranking_margin is not None
            and ranking_margin <= AMBIGUOUS_RANKING_MARGIN
            and result_topic_tokens[0].casefold() != result_topic_tokens[1].casefold()
        )

        return {
            "query": clean_query,
            "as_of": point_in_time,
            "min_score": threshold,
            "answerability_min_score": answerability_threshold,
            "answerability_rejected_count": answerability_rejected_count,
            "results": results,
            "gated_count": gated_count,
            "ranking_margin": ranking_margin,
            "ranking_ambiguous": ranking_ambiguous,
            "requested_top_k": top_k,
            "effective_top_k": effective_top_k,
            "competing_memory_detected": competing_memory_detected,
            "competing_pair_preserved": competing_memory_detected,
            "competing_pair_auto_expanded": competing_pair_auto_expanded,
            "competing_memory_groups": competing_groups,
            "competing_memory_groups_omitted": competing_groups_omitted,
            "lifecycle": lifecycle,
            "layers_involved": sorted(result_layers),
            "requested_layers": (
                [layer.value for layer in MemoryLayer]
                if requested_layers is None
                else [layer.value for layer in requested_layers]
            ),
            "expired_live_pruned": expired_live_pruned,
            "lifecycle_mutated": mutate_lifecycle,
            "memory_contract": {
                "minimal_ranked_context": True,
                "provenance_included": True,
                "shielded_layer_metadata": True,
                "protected_conflict_basis": True,
                "conflict_compatibility_inferred": False,
            },
        }

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
        """Recall protected logic roots, then traverse only authenticated links.

        Ordinary context traces are lifecycle-neutral.
        """

        return self.preview_context(
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
        """Trace protected context without changing any lifecycle state."""

        depth = _validate_context_bound(max_depth, "max_depth", MAX_CONTEXT_DEPTH)
        record_limit = _validate_context_bound(
            max_records,
            "max_records",
            MAX_CONTEXT_RECORDS,
        )
        root_recall = self.preview_recall(
            query,
            top_k=2,
            min_score=min_score,
            allow_inferential=allow_inferential,
            as_of=as_of,
            layers=[MemoryLayer.CONTEXTUAL_LOGIC.value],
        )
        response = _build_context_response(
            self._payloads,
            root_recall,
            max_depth=depth,
            max_records=record_limit,
        )
        response["lifecycle_mutated"] = False
        return response

    def forget(self, vine_id: str) -> dict[str, Any]:
        clean_id = _validate_text(vine_id, "vine_id", 128)
        dependent_ids = self._contextual_dependents(clean_id)
        cascaded: list[str] = []
        for dependent_id in dependent_ids:
            dependent_payload_deleted = self._payloads.delete(dependent_id)
            dependent_lifecycle_deleted = self.oracle.forget(dependent_id)
            if dependent_payload_deleted or dependent_lifecycle_deleted:
                cascaded.append(dependent_id)
        # Revoke content access before cleaning derived lifecycle state.
        payload_deleted = self._payloads.delete(clean_id)
        memory_deleted = self.oracle.forget(clean_id)
        return {
            "vine_id": clean_id,
            "forgotten": payload_deleted or memory_deleted or bool(cascaded),
            "payload_deleted": payload_deleted,
            "lifecycle_deleted": memory_deleted,
            "cascade_deleted_contextual_logic": cascaded,
        }

    def list_memories(
        self,
        *,
        limit: int = 1000,
        layers: list[str] | tuple[str, ...] | None = None,
        topic_prefix: str | None = None,
        newest_first: bool = False,
    ) -> list[dict[str, Any]]:
        """List a bounded authorized inventory without retrieval-side effects."""

        if not self._payloads.metadata_protected:
            raise RuntimeError(
                "legacy profiles are migration-only; fully shielded listing "
                "requires a scoped-v2 profile"
            )
        bounded_limit = _validate_context_bound(limit, "limit", 1000)
        requested_layers = _validate_memory_layers(layers)
        clean_prefix = (
            None
            if topic_prefix is None
            else _validate_text(topic_prefix, "topic_prefix", MAX_TOPIC_CHARS)
        )
        if not isinstance(newest_first, bool):
            raise TypeError("newest_first must be a boolean")
        self._prune_expired_live_memory()
        records = self._payloads.list_records(limit=1000)
        result: list[dict[str, Any]] = []
        for record in records:
            vine_id = str(record["vine_id"])
            try:
                contract = self._payloads.get_memory_contract(vine_id)
            except QuarantinedRecordError:
                continue
            if requested_layers is not None and contract.layer not in requested_layers:
                continue
            if clean_prefix is not None and not str(record["topic"]).startswith(
                clean_prefix
            ):
                continue
            result.append(
                {
                    **record,
                    **_public_record_contract(contract, str(record["payload"])),
                }
            )
        if newest_first:
            result.sort(
                key=lambda item: (
                    float(item["effective_at"]),
                    str(item["vine_id"]),
                ),
                reverse=True,
            )
        return result[:bounded_limit]

    def reindex(self) -> dict[str, Any]:
        if not self._payloads.metadata_protected:
            raise RuntimeError(
                "legacy profiles are migration-only; protected reindexing is unavailable"
            )
        started = time.perf_counter()
        record_ids = self._payloads.record_ids_for_reindex()
        updated = 0
        for vine_id in record_ids:
            topic, payload = self._payloads.record_for_reindex(vine_id)
            passages = _memory_passages(topic, payload)
            vectors = _embed_document_batch(self._embedder, passages)
            self._payloads.replace_retrieval_index(
                vine_id,
                f"{topic}\n{payload}",
                vectors,
            )
            updated += 1
            payload = ""
        return {
            "reindexed": updated,
            "embedding_model": self._embedder.model,
            "dimension": self._embedder.dimension,
            "retrieval_strategy": RETRIEVAL_SCHEMA_VERSION,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
        }

    def migrate_to(
        self, target: AgentMemory, *, confirm: bool = False
    ) -> dict[str, Any]:
        """Re-embed this profile into an empty target without plaintext exports."""
        if not isinstance(target, AgentMemory):
            raise TypeError("target must be an AgentMemory instance")
        if confirm is not True:
            raise ValueError("profile migration requires confirm=true")
        if target is self or os.path.samefile(target.profile_dir, self.profile_dir):
            raise ValueError("source and target profiles must be different")
        if (
            len(target._payloads)
            or target.oracle.workspace.vines
            or len(target.oracle.index)
            or len(target.oracle.archive)
        ):
            raise ValueError("target profile must be empty")

        records = self._payloads.records_for_migration()
        source_contracts: dict[str, MemoryLayerContract] = {}
        for record in records:
            payload = self._payloads.get(record.vine_id)
            if payload is None:
                raise RuntimeError("payload disappeared during migration preflight")
            try:
                source_contract = (
                    self._payloads.get_memory_contract(record.vine_id)
                    if self._payloads.metadata_protected
                    else None
                )
                policy_layer = (
                    MemoryLayer.SHORT_TERM
                    if source_contract is None
                    else source_contract.layer
                )
                _validate_memory_content_policy(
                    policy_layer,
                    payload,
                    operation="profile migration",
                )
                if source_contract is not None:
                    source_contracts[record.vine_id] = source_contract
            finally:
                payload = ""
        predecessors: dict[str, list[str]] = {}
        source_ids = {record.vine_id for record in records}
        for record in records:
            if record.superseded_by is not None:
                if record.superseded_by not in source_ids:
                    raise RuntimeError("source profile has a broken supersession link")
                predecessors.setdefault(record.superseded_by, []).append(record.vine_id)

        pending = {record.vine_id: record for record in records}
        migrated_ids: dict[str, str] = {}
        created_target_ids: list[str] = []
        started = time.perf_counter()
        try:
            while pending:
                progressed = False
                for source_id, record in list(pending.items()):
                    prior_ids = predecessors.get(source_id, [])
                    if any(prior_id not in migrated_ids for prior_id in prior_ids):
                        continue
                    payload = self._payloads.get(source_id)
                    if payload is None:
                        raise RuntimeError(
                            "payload disappeared during profile migration"
                        )
                    source_contract = source_contracts.get(source_id)
                    temporary_layer = (
                        MemoryLayer.LIVE
                        if source_contract is not None
                        and source_contract.layer == MemoryLayer.LIVE
                        else MemoryLayer.SHORT_TERM
                    )
                    try:
                        result = target.remember(
                            record.topic,
                            payload,
                            effective_at=record.effective_at,
                            supersedes=[
                                migrated_ids[prior_id] for prior_id in prior_ids
                            ],
                            layer=temporary_layer,
                            provenance=["migration:profile-transfer"],
                            expires_at=(
                                source_contract.expires_at
                                if temporary_layer == MemoryLayer.LIVE
                                and source_contract is not None
                                else None
                            ),
                        )
                    finally:
                        payload = ""
                    target_id = str(result["vine_id"])
                    migrated_ids[source_id] = target_id
                    created_target_ids.append(target_id)
                    del pending[source_id]
                    progressed = True
                if not progressed:
                    raise RuntimeError(
                        "source profile contains cyclic supersession history"
                    )
            if self._payloads.metadata_protected:
                for source_id, target_id in migrated_ids.items():
                    contract = source_contracts[source_id]
                    if contract.related_ids:
                        try:
                            related_ids = tuple(
                                migrated_ids[related_id]
                                for related_id in contract.related_ids
                            )
                        except KeyError as exc:
                            raise RuntimeError(
                                "source memory contract references an unknown record"
                            ) from exc
                        contract = MemoryLayerContract(
                            layer=contract.layer,
                            provenance=contract.provenance,
                            expires_at=contract.expires_at,
                            review_at=contract.review_at,
                            promotion_history=contract.promotion_history,
                            logic_kind=contract.logic_kind,
                            related_ids=related_ids,
                        )
                    target._payloads.set_memory_contract(target_id, contract)
        except Exception:
            for target_id in reversed(created_target_ids):
                target.forget(target_id)
            raise
        return {
            "migrated": len(migrated_ids),
            "source_profile": self.profile_dir.name,
            "target_profile": target.profile_dir.name,
            "source_embedding": self._embedder.model,
            "target_embedding": target._embedder.model,
            "history_links": sum(len(items) for items in predecessors.values()),
            "lifecycle_state_preserved": False,
            "plaintext_export_created": False,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
        }

    def rotate_key(
        self,
        *,
        confirm: bool = False,
        batch_size: int = 100,
    ) -> dict[str, Any]:
        """Start or resume a bounded, multi-key-safe local key rotation."""

        if confirm is not True:
            raise ValueError("key rotation requires confirm=true")
        if self._keyring is None or self._scoped_shield is None:
            raise RuntimeError(
                "legacy profiles must migrate to scoped-v2 before key rotation"
            )
        scoped_shield = self._scoped_shield
        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or not 1 <= batch_size <= 1000
        ):
            raise ValueError("rotation batch_size must be between 1 and 1000")
        current = self._keyring.rotation_state
        if current is not None and current["state"] == "verified":
            return {
                "state": "verified",
                "migrated_records": 0,
                "migrated_lifecycle_records": 0,
                "remaining_key_references": 0,
                "old_key_retained": True,
            }
        rotation = self._keyring.begin_rotation()
        source = rotation["from"]
        target = rotation["to"]

        def transform(value: object) -> ScopedProtectedVector:
            if not isinstance(value, ScopedProtectedVector):
                raise TypeError("rotation encountered an unsupported protected payload")
            return scoped_shield.reencrypt(value, target_key_id=target)

        active_migrated = self.oracle.rewrap_active_protected_anchors(
            source,
            transform,
        )
        if self._store is None:
            raise RuntimeError("lifecycle store is unavailable")
        lifecycle = self._store.rotate_protected_payloads(
            source_key_id=source,
            limit=batch_size,
            transform=transform,
        )
        payloads = self._payloads.rotate_batch(
            source_key_id=source,
            target_key_id=target,
            limit=batch_size,
        )
        remaining_payload = self._payloads.key_usage(source)
        remaining_lifecycle = self._store.count_protected_payloads_for_key(source)
        remaining = remaining_payload + remaining_lifecycle
        state = "migrating"
        if remaining == 0 and self._payloads.quarantine_count() == 0:
            self._keyring.mark_rotation_verified()
            state = "verified"
        return {
            "state": state,
            "migrated_records": payloads["migrated_records"],
            "migrated_tombstones": payloads["migrated_tombstones"],
            "failed_records": payloads["failed_records"],
            "migrated_lifecycle_records": (active_migrated + lifecycle["migrated"]),
            "remaining_key_references": remaining,
            "old_key_retained": True,
        }

    def retire_previous_key(
        self,
        *,
        confirm_backups_accounted_for: bool = False,
    ) -> dict[str, Any]:
        """Retire a verified old key only after storage and backups are checked."""

        if self._keyring is None or self._store is None:
            raise RuntimeError("legacy profiles do not support key retirement")
        rotation = self._keyring.rotation_state
        if rotation is None or rotation["state"] != "verified":
            raise RuntimeError("key rotation is not fully verified")
        source = rotation["from"]
        if self._payloads.key_usage(
            source
        ) or self._store.count_protected_payloads_for_key(source):
            raise RuntimeError("the previous key is still referenced by encrypted data")
        retired = self._keyring.retire_previous_key(
            confirm_backups_accounted_for=confirm_backups_accounted_for
        )
        return {
            "retired_key_id": retired,
            "backups_accounted_for": True,
            "physical_erasure_guaranteed": False,
        }

    @property
    def deployment_mode(self) -> str:
        """Return the explicitly configured local deployment class."""

        return self._deployment_mode

    def capabilities_v1(self) -> dict[str, Any]:
        """Return readiness diagnostics without changing preflight authority."""

        capabilities = self.doctor().get("capabilities_v1")
        if not isinstance(capabilities, dict):
            raise RuntimeError("capabilities_v1 report is unavailable")
        return dict(capabilities)

    def assert_operational_mode(self) -> None:
        """Block an explicitly requested but unqualified production boundary."""

        if self._deployment_mode != LOCAL_PRODUCTION_MODE:
            return
        capabilities = self.capabilities_v1()
        if capabilities.get("local_production_ready") is True:
            return
        codes = capabilities.get("remediation_codes", [])
        bounded = ",".join(str(code) for code in codes[:16])
        raise RuntimeError(
            "local-production readiness is blocked"
            + (f" ({bounded})" if bounded else "")
        )

    def _profile_access_verified(self) -> bool:
        """Observe profile ownership and owner-only access without repairing it."""

        return _profile_access_is_owner_only(self.profile_dir)

    def _embedding_identity_verified(self) -> bool:
        return bool(
            self._embedder.semantic
            and self._embedder.name == "ollama"
            and self._embedder.model.startswith("qwen3-embedding:")
            and _QWEN3_EMBEDDING_IDENTITY.fullmatch(self._embedder.identity)
        )

    def doctor(self) -> dict[str, Any]:
        capability = self.oracle.capability_report().as_dict()
        indexed_count, unindexed_count = self._payloads.retrieval_index_counts()
        layer_counts = self._payloads.memory_contract_counts()
        quarantine_count = self._payloads.quarantine_count()
        answerability_ready = self._embedder.semantic and (
            callable(getattr(self._embedder, "embed_retrieval_queries", None))
            or callable(getattr(self._embedder, "embed_answerability_query", None))
        )
        scoped = self._payloads.metadata_protected
        preflight_authority_id: str | None = None
        if scoped:
            from .preflight_receipt import PreflightReceiptAuthority

            preflight_authority_id = PreflightReceiptAuthority(
                self.profile_dir
            ).authority_id
        key_id = self._keyring.active_key_id if self._keyring is not None else "legacy"
        rotation_state = (
            self._keyring.rotation_state if self._keyring is not None else None
        )
        rotation_remaining = 0
        if rotation_state is not None:
            rotation_remaining = self._payloads.key_usage(rotation_state["from"])
            if self._store is not None:
                rotation_remaining += self._store.count_protected_payloads_for_key(
                    rotation_state["from"]
                )
        protected_contract_count = sum(layer_counts.values())
        contract_gap = max(0, len(self._payloads) - protected_contract_count)
        if self._store is None:
            raise RuntimeError("lifecycle store is unavailable")
        active_ids, indexed_ids, archived_ids, metadata_ids = (
            self._store.managed_state_ids()
        )
        if indexed_ids != archived_ids or indexed_ids != metadata_ids:
            raise RuntimeError("memory lifecycle tier integrity check failed")
        lifecycle_ids = active_ids | indexed_ids
        payload_ids = set(self._payloads.record_ids_for_reindex())
        unpaired_lifecycle_ids = lifecycle_ids.symmetric_difference(payload_ids)
        all_layers_shielded = (
            scoped and contract_gap == 0 and not unpaired_lifecycle_ids
        )
        rotation_ready = (
            all_layers_shielded and quarantine_count == 0 and unindexed_count == 0
        )
        profile_access_verified = self._profile_access_verified()
        implementation_healthy = (
            scoped
            and all_layers_shielded
            and self._restored_on_startup
            and quarantine_count == 0
            and unindexed_count == 0
            and profile_access_verified
        )
        effective_mode = self._deployment_mode if scoped else LEGACY_MIGRATION_MODE
        key_migration_complete = rotation_state is None or (
            rotation_state["state"] == "verified" and rotation_remaining == 0
        )
        capabilities_v1 = build_capabilities_v1(
            LocalReadinessState(
                configured_mode=effective_mode,
                implementation_healthy=implementation_healthy,
                at_rest_encrypted=all_layers_shielded,
                protected_semantic_state=(all_layers_shielded and unindexed_count == 0),
                embedding_identity_verified=self._embedding_identity_verified(),
                profile_access_verified=profile_access_verified,
                reconciliation_backlog=len(self._payloads.pending_ids()),
                quarantined_records=quarantine_count,
                plaintext_fallback_attempts=0,
                key_migration_complete=key_migration_complete,
                model_available=True,
                evidence=self._readiness_evidence,
            )
        )
        local_production_ready = bool(capabilities_v1["local_production_ready"])
        operational_healthy = implementation_healthy and (
            effective_mode != LOCAL_PRODUCTION_MODE or local_production_ready
        )
        remediation_codes = list(capabilities_v1.get("remediation_codes", []))
        return {
            "adapter_ready": operational_healthy,
            "mode": effective_mode,
            "crypto_environment": self.oracle.environment,
            "local_protection_ready": operational_healthy,
            "local_production_ready": local_production_ready,
            "production_ready": capabilities_v1["production_ready"],
            "profile": self.profile_dir.name,
            "protection_policy": "required",
            "security_schema": self._payloads.security_schema,
            "scope_bound": scoped,
            "preflight_receipt_schema": "echo-veil-preflight-v2",
            "preflight_authority_id": preflight_authority_id,
            "key_id": key_id,
            "payload_count": len(self._payloads),
            "active_count": len(self.oracle.workspace.vines),
            "archived_count": len(self.oracle.index),
            "key_owner_only": profile_access_verified,
            "store_permissions": ("valid" if profile_access_verified else "invalid"),
            "writer_serialization": "profile-sqlite-lease",
            "recovered_incomplete_lifecycle_records": (
                self._recovered_lifecycle_orphans
            ),
            "readiness": {
                "installed": True,
                "enabled": True,
                "crypto_initialized": scoped,
                "write_wired": scoped,
                "index_wired": scoped,
                "retrieval_wired": scoped,
                "persistence_wired": scoped,
                "restart_restored": self._restored_on_startup,
                "layer_contract_wired": all_layers_shielded,
                "context_trace_wired": all_layers_shielded,
                "competing_memory_wired": all_layers_shielded,
                "content_policy_wired": all_layers_shielded,
                "live_refresh_wired": all_layers_shielded,
                "preflight_receipt_wired": preflight_authority_id is not None,
                "rotation_ready": rotation_ready,
                "implementation_healthy": implementation_healthy,
                "local_production_ready": local_production_ready,
                "healthy": operational_healthy,
            },
            "rotation": {
                "state": "idle" if rotation_state is None else rotation_state["state"],
                "remaining_key_references": rotation_remaining,
            },
            "reconciliation_backlog": len(self._payloads.pending_ids()),
            "migrated_memory_contracts": self._migrated_memory_contracts,
            "authenticated_record_migrations": (self._authenticated_record_migrations),
            "expired_live_pruned": self._expired_live_pruned,
            "quarantined_records": quarantine_count,
            "failed_decryptions": quarantine_count,
            "authenticated_deletion_records": self._payloads.tombstone_count(),
            "plaintext_fallback_attempts": 0,
            "capabilities_v1": capabilities_v1,
            "readiness_remediation": remediation_messages(remediation_codes),
            "memory_layers": {
                "contract": MEMORY_CONTRACT_SCHEMA,
                "semantic_layers": [layer.value for layer in MemoryLayer],
                "all_records_shielded": all_layers_shielded,
                "protected_record_count": protected_contract_count,
                "unprotected_record_count": contract_gap,
                "unpaired_lifecycle_record_count": len(unpaired_lifecycle_ids),
                "counts": layer_counts,
                "promotion_policy": "explicit-live-to-short-to-long",
                "contextual_logic_links": "record-bound-encrypted",
                "layer_filtering": "authenticated-no-score-rewrite",
                "context_trace": "bounded-authenticated-outgoing-v1",
                "competing_memory": "bounded-authenticated-topic-v1",
                "content_policy": MEMORY_CONTENT_POLICY,
                "payload_limits_chars": {
                    "live": MAX_LIVE_MEMORY_CHARS,
                    "short_term": MAX_SHORT_TERM_MEMORY_CHARS,
                    "long_term": MAX_LONG_TERM_MEMORY_CHARS,
                    "contextual_logic": MAX_CONTEXTUAL_LOGIC_MEMORY_CHARS,
                },
                "raw_transcript_retention": "live-only",
                "automatic_content_rewriting": False,
                "live_refresh": "protected-supersession-or-renewal-v1",
            },
            "retrieval": {
                "strategy": RETRIEVAL_SCHEMA_VERSION,
                "protected_multivector_count": indexed_count,
                "unindexed_payload_count": unindexed_count,
                "candidate_limit": MAX_RETRIEVAL_CANDIDATES,
                "lexical_terms": "keyed-hash",
                "diversity_ranking": "topic-aware-mmr",
                "temporal_history": "explicit-supersession",
                "competing_memory": "possible-conflict-no-inference-v1",
                "answerability_gate": (
                    "semantic-predicate-v1" if answerability_ready else "unavailable"
                ),
                "answerability_min_score": (
                    DEFAULT_ANSWERABILITY_MIN_SCORE if answerability_ready else None
                ),
                "metadata": (
                    "opaque-authenticated" if scoped else "legacy-plaintext-topics"
                ),
            },
            "embedding": {
                "backend": self._embedder.name,
                "model": self._embedder.model,
                "dimension": self._embedder.dimension,
                "semantic": self._embedder.semantic,
                "default_min_score": self._embedder.default_min_score,
            },
            "capability_report": capability,
            "limitations": [
                *(
                    ["The hashing fallback is keyword-oriented, not a semantic model."]
                    if not self._embedder.semantic
                    else [
                        "Semantic recall quality is model- and corpus-dependent; "
                        "benchmark it before primary-memory use."
                    ]
                ),
                "Memory capture is opt-in; neither host is silently recorded.",
                *(
                    []
                    if scoped
                    else [
                        "This legacy profile retains plaintext topic metadata; "
                        "migrate it to a new scoped-v2 profile."
                    ]
                ),
                *(
                    []
                    if all_layers_shielded
                    else [
                        "The four-layer contract or lifecycle pairing is incomplete; "
                        "the adapter is not healthy until it is reconciled."
                    ]
                ),
                (
                    "Host-trusted local production is not the attested enclave "
                    "production profile."
                    if local_production_ready
                    else "AES-GCM local staging is not a qualified production profile."
                ),
                "Python cannot guarantee complete in-process plaintext zeroization.",
            ],
        }

    def _prune_expired_live_memory(self) -> int:
        """Remove expired Live records without promoting or archiving them."""

        if not self._payloads.metadata_protected:
            return 0
        expired: list[str] = []
        for vine_id in self._payloads.record_ids_for_reindex():
            try:
                contract = self._payloads.get_memory_contract(vine_id)
            except QuarantinedRecordError:
                continue
            if contract.layer == MemoryLayer.LIVE and contract.is_expired():
                expired.append(vine_id)
        for vine_id in expired:
            self.forget(vine_id)
        return len(expired)

    def _contextual_dependents(self, vine_id: str) -> list[str]:
        """Return transitive protected logic dependents in deletion order."""

        reverse_links: dict[str, list[str]] = {}
        for candidate_id in self._payloads.record_ids_for_reindex():
            try:
                contract = self._payloads.get_memory_contract(candidate_id)
            except QuarantinedRecordError:
                continue
            if contract.layer != MemoryLayer.CONTEXTUAL_LOGIC:
                continue
            for related_id in contract.related_ids:
                reverse_links.setdefault(related_id, []).append(candidate_id)

        ordered: list[str] = []
        seen = {vine_id}

        def visit(target_id: str) -> None:
            for dependent_id in sorted(reverse_links.get(target_id, ())):
                if dependent_id in seen:
                    continue
                seen.add(dependent_id)
                visit(dependent_id)
                ordered.append(dependent_id)

        visit(vine_id)
        return ordered

    def _managed_exists(self, vine_id: str) -> bool:
        lifecycle_exists = (
            self.oracle.workspace.get(vine_id) is not None
            or self.oracle.archived_metadata(vine_id) is not None
        )
        if not lifecycle_exists:
            return False
        return vine_id in set(self._payloads.record_ids_for_reindex())

    def _recover_incomplete_operations(self) -> int:
        if self._store is None:
            raise RuntimeError("lifecycle store is unavailable")
        active, indexed, archived, metadata = self._store.managed_state_ids()
        if indexed != archived or indexed != metadata or active & indexed:
            raise RuntimeError("memory lifecycle tier integrity check failed")
        pending_ids = set(self._payloads.pending_ids())
        managed_ids = active | indexed
        for vine_id in sorted(pending_ids):
            if vine_id in managed_ids:
                self._payloads.mark_committed(vine_id)
            else:
                self._payloads.delete(vine_id, tombstone=False)
        payload_ids = set(self._payloads.record_ids_for_reindex())
        if payload_ids - managed_ids:
            raise RuntimeError(
                "encrypted payload records are missing lifecycle state; "
                "automatic deletion is refused"
            )
        incomplete = sorted(managed_ids - payload_ids)
        for vine_id in incomplete:
            self.oracle.forget(vine_id)
        return len(incomplete)

    def _bind_embedding_identity(self) -> None:
        stored = self._payloads.get_metadata("embedding_identity")
        has_managed_state = bool(
            len(self._payloads)
            or self.oracle.workspace.vines
            or len(self.oracle.index)
            or len(self.oracle.archive)
        )
        if stored is None and has_managed_state:
            legacy = HashingTextEmbedder()
            if self._embedder.identity != legacy.identity:
                raise RuntimeError(
                    "profile contains legacy hashing embeddings; use the hashing "
                    "backend to export/forget them or select a new semantic profile"
                )
            stored = legacy.identity
        if stored is None:
            self._payloads.set_metadata("embedding_identity", self._embedder.identity)
            stored = self._payloads.get_metadata("embedding_identity")
        if stored != self._embedder.identity:
            raise RuntimeError(
                "embedding identity does not match this profile; use a new profile "
                "or perform an explicit re-embedding migration"
            )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._payloads.close()
        finally:
            try:
                if self._store is not None:
                    self._store.close()
            finally:
                self._lease.close()

    def __enter__(self) -> AgentMemory:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class AlwaysAvailableMemory:
    """Read-only encrypted lexical recall for a pre-existing local profile.

    This layer never creates a profile, embeds text, mutates lifecycle state, or
    presents lexical overlap as semantic recall. It is intended only for bounded
    degraded operation while the configured embedding service is unavailable.
    """

    def __init__(
        self,
        state_dir: str | os.PathLike[str] | None = None,
        *,
        profile: str = "default",
        scope: str = "local-user",
        reason: str = "embedding_service_unavailable",
    ) -> None:
        profile_name = _validate_profile(profile)
        self.reason = _validate_text(reason, "availability reason", 128)
        base = (
            default_state_dir() if state_dir is None else Path(state_dir).expanduser()
        )
        profile_dir = (base / profile_name).absolute()
        _reject_symlink_components(profile_dir)
        if profile_dir.is_symlink() or not profile_dir.is_dir():
            raise RuntimeError(
                "always-available recall requires an existing local profile"
            )
        if os.name == "nt":
            try:
                _windows_verify_private_directory(profile_dir)
            except OSError as exc:
                raise RuntimeError(
                    "availability profile directory Windows DACL is unsafe"
                ) from exc
        elif stat.S_IMODE(profile_dir.stat().st_mode) & 0o077:
            raise RuntimeError("availability profile directory must be owner-only")
        self.profile_dir = profile_dir.absolute()
        payload_path = self.profile_dir / "payloads.db"
        if _payload_database_version(payload_path) == LEGACY_PAYLOAD_SCHEMA_VERSION:
            raise RuntimeError(
                "always-available recall requires a scoped-v2 profile because "
                "legacy topic and layer metadata are not fully shielded"
            )
        else:
            self._keyring = ProfileKeyring(
                self.profile_dir,
                scope,
                create=False,
            )
            self._payloads = _EncryptedPayloadStore(
                payload_path,
                keyring=self._keyring,
                read_only=True,
            )
            self._payloads.initialize_memory_contracts()
            self._payloads.initialize_record_integrity()

    @property
    def scope(self) -> str:
        """Return the authenticated logical authorization scope."""

        return self._keyring.scope

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
        del (
            topic,
            payload,
            effective_at,
            supersedes,
            layer,
            provenance,
            promotion_reason,
            expires_at,
            logic_kind,
            related_ids,
        )
        raise RuntimeError("remember is unavailable in read-only always-available mode")

    def promote(
        self,
        vine_id: str,
        target_layer: MemoryLayer | str,
        *,
        reason: str,
        provenance: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        del vine_id, target_layer, reason, provenance
        raise RuntimeError("promote is unavailable in read-only always-available mode")

    def refresh_live(
        self,
        vine_id: str,
        payload: str,
        *,
        provenance: list[str] | tuple[str, ...] | None = None,
        expires_at: float | None = None,
    ) -> dict[str, Any]:
        del vine_id, payload, provenance, expires_at
        raise RuntimeError(
            "refresh_live is unavailable in read-only always-available mode"
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
        clean_query = _validate_text(query, "query", MAX_QUERY_CHARS)
        if isinstance(top_k, bool) or not isinstance(top_k, int):
            raise TypeError("top_k must be an integer")
        if not 1 <= top_k <= MAX_RECALL_RESULTS:
            raise ValueError(f"top_k must be between 1 and {MAX_RECALL_RESULTS}")
        if min_score is None:
            threshold = DEFAULT_AVAILABILITY_MIN_SCORE
        elif isinstance(min_score, bool) or not isinstance(min_score, (int, float)):
            raise TypeError("min_score must be a finite number or None")
        else:
            threshold = float(min_score)
        if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
            raise ValueError("min_score must be between 0 and 1")
        if threshold < DEFAULT_AVAILABILITY_MIN_SCORE:
            raise ValueError(
                "always-available min_score cannot be lower than the safe default"
            )
        if allow_inferential is not False:
            raise ValueError(
                "inferential recall is unavailable without semantic verification"
            )
        point_in_time = _validate_optional_timestamp(as_of, "as_of")
        requested_layers = _validate_memory_layers(layers)
        candidates = _prioritize_competing_candidates(
            self._payloads.availability_candidates(
                clean_query,
                as_of=point_in_time,
            )
        )
        results: list[dict[str, Any]] = []
        result_candidates: list[_AvailabilityCandidate] = []
        expired_live_suppressed = 0
        scan_limit = 2 if top_k == 1 else top_k
        for candidate in candidates:
            if candidate.predicate_score < threshold:
                continue
            if candidate.matched_features < MIN_AVAILABILITY_FEATURES:
                continue
            try:
                contract = self._payloads.get_memory_contract(candidate.vine_id)
                record = self._payloads.get_record(candidate.vine_id)
            except QuarantinedRecordError:
                continue
            if contract.is_expired():
                expired_live_suppressed += 1
                continue
            if requested_layers is not None and contract.layer not in requested_layers:
                continue
            if record is None:
                continue
            topic, payload = record
            confidence_score = _availability_confidence(candidate.score)
            policy = classify(confidence_score)
            results.append(
                {
                    "rank": len(results) + 1,
                    "vine_id": candidate.vine_id,
                    "topic": topic,
                    "topic_protected": self._payloads.metadata_protected,
                    "score": round(confidence_score, 6),
                    "availability_score": round(candidate.score, 6),
                    "semantic_score": None,
                    "answerability_score": None,
                    "lexical_score": round(candidate.lexical_score, 6),
                    "predicate_score": round(candidate.predicate_score, 6),
                    "matched_features": candidate.matched_features,
                    "source": "encrypted-keyed-index",
                    "temporal_status": (
                        "valid_at_as_of"
                        if point_in_time is not None
                        else ("current" if candidate.temporal_current else "superseded")
                    ),
                    "effective_at": candidate.effective_at,
                    "superseded_by": candidate.superseded_by,
                    "superseded_at": candidate.superseded_at,
                    "confidence_band": policy.band.value,
                    "confidence_indicator": (
                        "Degraded keyed match; semantic verification offline."
                    ),
                    "gated": False,
                    "payload": payload,
                    **_public_record_contract(contract, payload),
                }
            )
            result_candidates.append(candidate)
            if len(results) >= scan_limit:
                break
        competing_pair_auto_expanded = (
            top_k == 1
            and len(result_candidates) >= 2
            and _is_competing_pair(result_candidates[0], result_candidates[1])
        )
        effective_top_k = 2 if competing_pair_auto_expanded else top_k
        if len(results) > effective_top_k:
            del results[effective_top_k:]
            del result_candidates[effective_top_k:]
        for rank, result in enumerate(results, start=1):
            result["rank"] = rank
        competing_groups, competing_groups_omitted = _annotate_competing_memories(
            results,
            result_candidates,
        )
        competing_memory_detected = bool(competing_groups)
        result_layers = {
            str(result["memory_layer"])
            for result in results
            if isinstance(result.get("memory_layer"), str)
        }
        return {
            "query": clean_query,
            "as_of": point_in_time,
            "mode": "always-available-read-only",
            "degraded": True,
            "degraded_reason": self.reason,
            "semantic_available": False,
            "lifecycle_mutated": False,
            "availability_strategy": "encrypted-keyed-predicate-v1",
            "min_score": threshold,
            "minimum_matched_features": MIN_AVAILABILITY_FEATURES,
            "results": results,
            "gated_count": 0,
            "ranking_margin": None,
            "ranking_ambiguous": False,
            "requested_top_k": top_k,
            "effective_top_k": effective_top_k,
            "competing_memory_detected": competing_memory_detected,
            "competing_pair_preserved": competing_memory_detected,
            "competing_pair_auto_expanded": competing_pair_auto_expanded,
            "competing_memory_groups": competing_groups,
            "competing_memory_groups_omitted": competing_groups_omitted,
            "layers_involved": sorted(result_layers),
            "requested_layers": (
                [layer.value for layer in MemoryLayer]
                if requested_layers is None
                else [layer.value for layer in requested_layers]
            ),
            "expired_live_suppressed": expired_live_suppressed,
            "memory_contract": {
                "minimal_ranked_context": True,
                "provenance_included": True,
                "shielded_layer_metadata": True,
                "protected_conflict_basis": True,
                "conflict_compatibility_inferred": False,
            },
            "limitations": [
                "Only strong keyed lexical and predicate overlap is available.",
                "Paraphrases may be missed until semantic recall is restored.",
                "Recall does not mutate Echo Veil lifecycle state in this mode.",
            ],
        }

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
        depth = _validate_context_bound(max_depth, "max_depth", MAX_CONTEXT_DEPTH)
        record_limit = _validate_context_bound(
            max_records,
            "max_records",
            MAX_CONTEXT_RECORDS,
        )
        root_recall = self.recall(
            query,
            top_k=2,
            min_score=min_score,
            allow_inferential=allow_inferential,
            as_of=as_of,
            layers=[MemoryLayer.CONTEXTUAL_LOGIC.value],
        )
        return _build_context_response(
            self._payloads,
            root_recall,
            max_depth=depth,
            max_records=record_limit,
        )

    def forget(self, vine_id: str) -> dict[str, Any]:
        del vine_id
        raise RuntimeError("forget is unavailable in read-only always-available mode")

    def list_memories(
        self,
        *,
        limit: int = 1000,
        layers: list[str] | tuple[str, ...] | None = None,
        topic_prefix: str | None = None,
        newest_first: bool = False,
    ) -> list[dict[str, Any]]:
        bounded_limit = _validate_context_bound(limit, "limit", 1000)
        requested_layers = _validate_memory_layers(layers)
        clean_prefix = (
            None
            if topic_prefix is None
            else _validate_text(topic_prefix, "topic_prefix", MAX_TOPIC_CHARS)
        )
        if not isinstance(newest_first, bool):
            raise TypeError("newest_first must be a boolean")
        records = self._payloads.list_records(limit=1000)
        result: list[dict[str, Any]] = []
        for record in records:
            try:
                contract = self._payloads.get_memory_contract(str(record["vine_id"]))
            except QuarantinedRecordError:
                continue
            if contract.is_expired():
                continue
            if requested_layers is not None and contract.layer not in requested_layers:
                continue
            if clean_prefix is not None and not str(record["topic"]).startswith(
                clean_prefix
            ):
                continue
            result.append(
                {
                    **record,
                    **_public_record_contract(contract, str(record["payload"])),
                }
            )
        if newest_first:
            result.sort(
                key=lambda item: (
                    float(item["effective_at"]),
                    str(item["vine_id"]),
                ),
                reverse=True,
            )
        return result[:bounded_limit]

    def reindex(self) -> dict[str, Any]:
        raise RuntimeError("reindex is unavailable in read-only always-available mode")

    def capabilities_v1(self) -> dict[str, Any]:
        capabilities = self.doctor().get("capabilities_v1")
        if not isinstance(capabilities, dict):
            raise RuntimeError("capabilities_v1 report is unavailable")
        return dict(capabilities)

    def doctor(self) -> dict[str, Any]:
        indexed_count, unindexed_count = self._payloads.retrieval_index_counts()
        layer_counts = self._payloads.memory_contract_counts()
        quarantine_count = self._payloads.quarantine_count()
        all_records_shielded = self._payloads.metadata_protected and sum(
            layer_counts.values()
        ) == len(self._payloads)
        rotation_state = self._keyring.rotation_state
        profile_access_verified = _profile_access_is_owner_only(self.profile_dir)
        capabilities_v1 = build_capabilities_v1(
            LocalReadinessState(
                configured_mode=OFFLINE_READ_ONLY_MODE,
                implementation_healthy=(all_records_shielded and quarantine_count == 0),
                at_rest_encrypted=all_records_shielded,
                protected_semantic_state=(
                    all_records_shielded and unindexed_count == 0
                ),
                embedding_identity_verified=False,
                profile_access_verified=profile_access_verified,
                reconciliation_backlog=0,
                quarantined_records=quarantine_count,
                plaintext_fallback_attempts=0,
                key_migration_complete=(
                    rotation_state is None or rotation_state["state"] == "verified"
                ),
                model_available=False,
            )
        )
        return {
            "adapter_ready": True,
            "mode": "always-available-read-only",
            "mode_alias": OFFLINE_READ_ONLY_MODE,
            "local_protection_ready": False,
            "local_production_ready": False,
            "production_ready": False,
            "degraded": True,
            "degraded_reason": self.reason,
            "profile": self.profile_dir.name,
            "payload_count": len(self._payloads),
            "security_schema": self._payloads.security_schema,
            "scope_bound": self._payloads.metadata_protected,
            "key_id": (
                self._keyring.active_key_id if self._keyring is not None else "legacy"
            ),
            "key_owner_only": profile_access_verified,
            "semantic_available": False,
            "writes_available": False,
            "lifecycle_mutation_available": False,
            "capabilities_v1": capabilities_v1,
            "readiness_remediation": remediation_messages(
                list(capabilities_v1.get("remediation_codes", []))
            ),
            "memory_layers": {
                "contract": MEMORY_CONTRACT_SCHEMA,
                "semantic_layers": [layer.value for layer in MemoryLayer],
                "all_records_shielded": all_records_shielded,
                "counts": layer_counts,
                "lifecycle_mutation_available": False,
                "layer_filtering": "authenticated-no-score-rewrite",
                "context_trace": "bounded-authenticated-outgoing-v1",
                "competing_memory": "bounded-authenticated-topic-v1",
                "content_policy": MEMORY_CONTENT_POLICY,
                "payload_limits_chars": {
                    "live": MAX_LIVE_MEMORY_CHARS,
                    "short_term": MAX_SHORT_TERM_MEMORY_CHARS,
                    "long_term": MAX_LONG_TERM_MEMORY_CHARS,
                    "contextual_logic": MAX_CONTEXTUAL_LOGIC_MEMORY_CHARS,
                },
                "raw_transcript_retention": "live-only",
                "automatic_content_rewriting": False,
                "live_refresh": "unavailable-read-only",
            },
            "quarantined_records": quarantine_count,
            "retrieval": {
                "strategy": "encrypted-keyed-predicate-v1",
                "protected_multivector_count": indexed_count,
                "unindexed_payload_count": unindexed_count,
                "candidate_limit": MAX_RETRIEVAL_CANDIDATES,
                "lexical_terms": "keyed-hash",
                "competing_memory": "possible-conflict-no-inference-v1",
                "minimum_score": DEFAULT_AVAILABILITY_MIN_SCORE,
                "minimum_matched_features": MIN_AVAILABILITY_FEATURES,
            },
            "limitations": [
                "Semantic embeddings and answerability verification are offline.",
                "Only conservative keyed lexical recall is available.",
                "Remember, forget, reindex, and lifecycle mutation are disabled.",
                "Restart the adapter after the embedding service is restored.",
            ],
        }

    def close(self) -> None:
        self._payloads.close()

    def __enter__(self) -> AlwaysAvailableMemory:
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


def _coerce_embedder(
    embed: TextEmbedder | Callable[[str], NDArray[np.float64]] | None,
    embedder_id: str | None,
) -> TextEmbedder:
    if embed is None:
        if embedder_id is not None:
            raise ValueError("embedder_id requires a custom embedding callable")
        return HashingTextEmbedder()
    if isinstance(embed, TextEmbedder):
        if embedder_id is not None:
            raise ValueError(
                "embedder_id is only valid for a custom embedding callable"
            )
        _validate_embedder_contract(embed)
        return embed
    if not callable(embed):
        raise TypeError("embed must implement TextEmbedder or be callable")
    if embedder_id is None:
        raise ValueError(
            "custom embedding callables require a stable embedder_id for persistence"
        )
    return _CallableTextEmbedder(embed, embedder_id)


def _validate_embedder_contract(embedder: TextEmbedder) -> None:
    _validate_text(embedder.identity, "embedding identity", 2048)
    _validate_text(embedder.name, "embedding backend name", 128)
    _validate_text(embedder.model, "embedding model", 256)
    if isinstance(embedder.dimension, bool) or not isinstance(embedder.dimension, int):
        raise TypeError("embedding dimension must be a positive integer")
    if embedder.dimension <= 0:
        raise ValueError("embedding dimension must be a positive integer")
    if not isinstance(embedder.semantic, bool):
        raise TypeError("embedding semantic flag must be a bool")
    score = embedder.default_min_score
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise TypeError("embedding default_min_score must be a finite number")
    if not math.isfinite(float(score)) or not 0.0 <= float(score) <= 1.0:
        raise ValueError("embedding default_min_score must be between 0 and 1")


def _normalize_embedding_vector(
    value: NDArray[np.float64],
    *,
    expected_dimension: int | None = None,
    source: str = "embedder",
) -> NDArray[np.float64]:
    try:
        vector = np.asarray(value, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{source} returned an invalid embedding vector") from exc
    if vector.ndim != 1 or vector.size == 0 or not np.all(np.isfinite(vector)):
        raise ValueError(f"{source} returned an invalid embedding vector")
    if expected_dimension is not None and vector.shape != (expected_dimension,):
        raise ValueError(
            f"{source} returned dimension {vector.size}; expected {expected_dimension}"
        )
    magnitude = float(np.linalg.norm(vector))
    if not math.isfinite(magnitude) or magnitude == 0.0:
        raise ValueError(f"{source} returned an unusable embedding vector")
    return vector / magnitude


def _embed_document_batch(
    embedder: TextEmbedder,
    passages: list[str],
) -> list[NDArray[np.float64]]:
    batch = getattr(embedder, "embed_documents", None)
    if callable(batch):
        raw_vectors = batch(passages)
    else:
        raw_vectors = [embedder.embed_document(passage) for passage in passages]
    if not isinstance(raw_vectors, list) or len(raw_vectors) != len(passages):
        raise ValueError("embedder returned an invalid document batch")
    return [
        _normalize_embedding_vector(
            vector,
            expected_dimension=embedder.dimension,
        )
        for vector in raw_vectors
    ]


def _memory_passages(topic: str, payload: str) -> list[str]:
    prefix = f"Memory topic: {topic}\nMemory content: "
    if len(prefix) + len(payload) <= MAX_PASSAGE_CHARS:
        return [prefix + payload]

    chunks: list[str] = []
    cursor = 0
    available = max(128, MAX_PASSAGE_CHARS - len(prefix))
    while cursor < len(payload):
        end = min(len(payload), cursor + available)
        if end < len(payload):
            split = payload.rfind(" ", cursor, end)
            if split > cursor + available // 2:
                end = split
        chunk = payload[cursor:end].strip()
        if chunk:
            chunks.append(prefix + chunk)
        cursor = max(end, cursor + 1)
        while cursor < len(payload) and payload[cursor].isspace():
            cursor += 1

    if len(chunks) <= MAX_MEMORY_PASSAGES:
        return chunks
    selected: list[str] = []
    for index in range(MAX_MEMORY_PASSAGES):
        position = round(index * (len(chunks) - 1) / (MAX_MEMORY_PASSAGES - 1))
        selected.append(chunks[position])
    return selected


def _memory_payload_limit(layer: MemoryLayer) -> int:
    limits = {
        MemoryLayer.LIVE: MAX_LIVE_MEMORY_CHARS,
        MemoryLayer.SHORT_TERM: MAX_SHORT_TERM_MEMORY_CHARS,
        MemoryLayer.LONG_TERM: MAX_LONG_TERM_MEMORY_CHARS,
        MemoryLayer.CONTEXTUAL_LOGIC: MAX_CONTEXTUAL_LOGIC_MEMORY_CHARS,
    }
    return limits[layer]


def _looks_like_raw_transcript(payload: str) -> bool:
    role_lines = _TRANSCRIPT_ROLE_LINE.findall(payload)
    if len(role_lines) >= 2 and len({role.casefold() for role in role_lines}) >= 2:
        return True
    if len(_TRANSCRIPT_JSON_ROLE.findall(payload)) >= 2:
        return True
    return payload.count("<|im_start|>") >= 2 or payload.count("<|im_end|>") >= 2


def _memory_content_policy(
    layer: MemoryLayer,
    payload: str,
) -> dict[str, Any]:
    raw_transcript = _looks_like_raw_transcript(payload)
    within_layer_limit = len(payload) <= _memory_payload_limit(layer)
    policy_compliant = within_layer_limit and (
        layer == MemoryLayer.LIVE or not raw_transcript
    )
    long_term_ready = len(payload) <= MAX_LONG_TERM_MEMORY_CHARS and not raw_transcript
    return {
        "policy": MEMORY_CONTENT_POLICY,
        "character_count": len(payload),
        "layer_character_limit": _memory_payload_limit(layer),
        "raw_transcript_detected": raw_transcript,
        "policy_compliant": policy_compliant,
        "long_term_ready": long_term_ready,
        "compaction_required_for_promotion": (
            layer != MemoryLayer.LONG_TERM and not long_term_ready
        ),
        "automatic_rewriting_performed": False,
    }


def _validate_memory_content_policy(
    layer: MemoryLayer,
    payload: str,
    *,
    operation: str,
) -> None:
    limit = _memory_payload_limit(layer)
    if len(payload) > limit:
        raise ValueError(
            f"{operation} exceeds the {limit}-character {layer.value} memory "
            "limit; keep full source material in the authorized host store and "
            "write a compact intent/outcome memory"
        )
    if layer != MemoryLayer.LIVE and _looks_like_raw_transcript(payload):
        raise ValueError(
            f"{operation} appears to contain a raw transcript; keep the transcript "
            "in the authorized host source and write a compact seed crystal"
        )


def _public_record_contract(
    contract: MemoryLayerContract,
    payload: str,
) -> dict[str, Any]:
    public = _public_contract(contract)
    content_policy = _memory_content_policy(contract.layer, payload)
    if (
        contract.layer == MemoryLayer.LIVE
        and content_policy["compaction_required_for_promotion"] is True
    ):
        public["promotion_recommendation"] = (
            "compact_before_short_term_promotion_or_discard"
        )
    elif (
        contract.layer == MemoryLayer.SHORT_TERM
        and content_policy["compaction_required_for_promotion"] is True
    ):
        public["promotion_recommendation"] = (
            "compact_seed_crystal_before_long_term_promotion"
        )
    public["content_policy"] = content_policy
    return public


def _lexical_features(text: str, limit: int) -> dict[str, int]:
    tokens = [
        token
        for token in _TOKEN_PATTERN.findall(text.casefold())
        if token not in _STOPWORDS and len(token) > 1
    ]
    features = [f"t:{token}" for token in tokens]
    features.extend(
        f"b:{left}\0{right}" for left, right in zip(tokens, tokens[1:], strict=False)
    )
    counts: dict[str, int] = {}
    for feature in features:
        if feature not in counts and len(counts) >= limit:
            continue
        counts[feature] = min(255, counts.get(feature, 0) + 1)
    return counts


def _hybrid_relevance(semantic_score: float | None, lexical_score: float) -> float:
    semantic = 0.0 if semantic_score is None else min(1.0, max(0.0, semantic_score))
    lexical = min(1.0, max(0.0, lexical_score))
    return min(1.0, semantic + LEXICAL_BOOST * lexical * (1.0 - semantic))


def _answerability_relevance(
    relevance_score: float,
    answerability_score: float | None,
) -> float:
    """Add bounded confidence only after an independent answerability pass."""
    relevance = min(1.0, max(0.0, relevance_score))
    if answerability_score is None:
        return relevance
    answerability = min(1.0, max(0.0, answerability_score))
    return min(
        1.0,
        relevance + ANSWERABILITY_BOOST * answerability * (1.0 - relevance),
    )


def _availability_confidence(availability_score: float) -> float:
    """Map a qualified raw lexical score into the non-authoritative safe band."""
    bounded = min(1.0, max(DEFAULT_AVAILABILITY_MIN_SCORE, availability_score))
    progress = (bounded - DEFAULT_AVAILABILITY_MIN_SCORE) / (
        1.0 - DEFAULT_AVAILABILITY_MIN_SCORE
    )
    return 0.50 + 0.19 * progress


def _predicate_query(query: str) -> str:
    """Mask grammatical subjects while retaining the requested fact or rule.

    The transform is deliberately syntax-only: it does not contain user names,
    domain vocabularies, or sensitive-attribute lists. This prevents a common
    failure where a person's identity dominates a query about an absent fact.
    """
    focused = re.sub(
        r"\b(?i:does|do|did)\s+(?:the\s+)?(?:[\w'’-]+\s+){0,3}(?i:have)\b",
        "is there",
        query,
    )
    focused = re.sub(
        r"\b[^\W\d_]+(?:-[^\W\d_]+)*(?:['’]s)\b",
        "",
        focused,
    )
    focused = re.sub(
        r"\b((?i:does|do|did|is|was|has))\s+([A-Z][\w'’-]*)\b",
        r"\1",
        focused,
    )
    focused = re.sub(
        r"(^|[.!?]\s+)((?i:may|should|can|would|will))\s+"
        r"([A-Z][\w'’-]*)\b",
        r"\1\2",
        focused,
    )
    focused = re.sub(r"\s+", " ", focused).replace(" ?", "?").strip()
    return focused or query


def _mmr_rank(candidates: list[_RankedCandidate]) -> list[_RankedCandidate]:
    remaining = list(candidates)
    selected: list[_RankedCandidate] = []
    while remaining:

        def selection_key(candidate: _RankedCandidate) -> tuple[int, float, float]:
            diversity = 0.0
            if candidate.best_vector is not None:
                similarities = [
                    cosine_similarity(candidate.best_vector, prior.best_vector)
                    for prior in selected
                    if prior.best_vector is not None
                    and prior.topic.casefold() != candidate.topic.casefold()
                ]
                diversity = max(similarities, default=0.0)
            mmr = MMR_RELEVANCE_WEIGHT * candidate.relevance_score - (
                1.0 - MMR_RELEVANCE_WEIGHT
            ) * max(0.0, diversity)
            return (
                1 if candidate.temporal_current else 0,
                mmr,
                candidate.effective_at,
            )

        winner = max(remaining, key=selection_key)
        selected.append(winner)
        remaining.remove(winner)
    return selected


def _prioritize_competing_candidates(
    candidates: Sequence[_CompetingCandidateT],
) -> list[_CompetingCandidateT]:
    """Keep the strongest current same-topic partner beside its first result."""

    remaining = list(candidates)
    prioritized: list[_CompetingCandidateT] = []
    while remaining:
        candidate = remaining.pop(0)
        prioritized.append(candidate)
        if not candidate.temporal_current:
            continue
        protected_topic = candidate.topic.casefold()
        partner_index = next(
            (
                index
                for index, possible_partner in enumerate(remaining)
                if possible_partner.temporal_current
                and possible_partner.topic.casefold() == protected_topic
            ),
            None,
        )
        if partner_index is not None:
            prioritized.append(remaining.pop(partner_index))
    return prioritized


def _is_competing_pair(
    first: _CompetingCandidate,
    second: _CompetingCandidate,
) -> bool:
    return (
        first.temporal_current
        and second.temporal_current
        and first.vine_id != second.vine_id
        and first.topic.casefold() == second.topic.casefold()
    )


def _annotate_competing_memories(
    results: list[dict[str, Any]],
    candidates: Sequence[_CompetingCandidate],
) -> tuple[list[dict[str, Any]], int]:
    """Label bounded same-topic groups without claiming semantic contradiction."""

    if len(results) != len(candidates):
        raise RuntimeError("recall result and protected topic metadata diverged")
    for result in results:
        result["possible_conflict"] = False
        result["competing_memory_group"] = None

    grouped_indexes: dict[str, list[int]] = {}
    for index, candidate in enumerate(candidates):
        if candidate.temporal_current:
            grouped_indexes.setdefault(candidate.topic.casefold(), []).append(index)
    competing = [indexes for indexes in grouped_indexes.values() if len(indexes) >= 2]
    competing.sort(key=lambda indexes: indexes[0])
    visible_groups = competing[:MAX_COMPETING_MEMORY_GROUPS]
    groups: list[dict[str, Any]] = []
    for ordinal, indexes in enumerate(visible_groups, start=1):
        group_id = f"competing-{ordinal}"
        for index in indexes:
            results[index]["possible_conflict"] = True
            results[index]["competing_memory_group"] = group_id
        member_ids = [str(results[index]["vine_id"]) for index in indexes]
        groups.append(
            {
                "group_id": group_id,
                "status": "possible_conflict",
                "returned_member_count": len(member_ids),
                "member_ids": member_ids[:MAX_COMPETING_MEMORY_IDS],
                "member_ids_truncated": len(member_ids) > MAX_COMPETING_MEMORY_IDS,
                "basis": (
                    "Multiple returned current records share one authenticated "
                    "protected topic; compatibility was not inferred."
                ),
                "protected_topic_basis": True,
                "topic_exposed": False,
                "resolution_status": "not_evaluated",
                "resolution_guidance": (
                    "Preserve and review every returned member. Explicitly "
                    "supersede an obsolete fact, or store a protected Contextual "
                    "Logic contradiction_resolution that links the evidence."
                ),
            }
        )
    return groups, max(0, len(competing) - len(visible_groups))


def _round_optional(value: float | None) -> float | None:
    return None if value is None else round(value, 6)


def _build_context_response(
    payloads: _EncryptedPayloadStore,
    root_recall: dict[str, Any],
    *,
    max_depth: int,
    max_records: int,
) -> dict[str, Any]:
    """Expand only authenticated outgoing links from confidence-checked roots."""

    raw_roots = root_recall.get("results")
    roots = list(raw_roots) if isinstance(raw_roots, list) else []
    point_in_time_raw = root_recall.get("as_of")
    point_in_time = (
        float(point_in_time_raw)
        if isinstance(point_in_time_raw, (int, float))
        and not isinstance(point_in_time_raw, bool)
        else None
    )
    queue: deque[tuple[str, str, int, str, tuple[str, ...]]] = deque()
    root_expansion: list[dict[str, Any]] = []
    visited = {
        str(root["vine_id"])
        for root in roots
        if isinstance(root, dict) and isinstance(root.get("vine_id"), str)
    }
    incomplete = False

    for root in roots:
        if not isinstance(root, dict) or not isinstance(root.get("vine_id"), str):
            incomplete = True
            continue
        root_id = str(root["vine_id"])
        if root.get("gated") is True:
            root_expansion.append(
                {
                    "vine_id": root_id,
                    "expanded": False,
                    "status": "confidence_gated",
                }
            )
            incomplete = True
            continue
        try:
            contract = payloads.get_memory_contract(root_id)
        except QuarantinedRecordError:
            root_expansion.append(
                {
                    "vine_id": root_id,
                    "expanded": False,
                    "status": "authentication_failed",
                }
            )
            incomplete = True
            continue
        if (
            contract.layer != MemoryLayer.CONTEXTUAL_LOGIC
            or contract.logic_kind is None
        ):
            root_expansion.append(
                {
                    "vine_id": root_id,
                    "expanded": False,
                    "status": "invalid_logic_root",
                }
            )
            incomplete = True
            continue
        root_expansion.append(
            {
                "vine_id": root_id,
                "expanded": True,
                "status": "authenticated",
            }
        )
        for related_id in contract.related_ids:
            queue.append(
                (
                    root_id,
                    related_id,
                    1,
                    contract.logic_kind.value,
                    (root_id,),
                )
            )

    evidence: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    while queue and len(evidence) < max_records and len(edges) < MAX_CONTEXT_EDGES:
        parent_id, target_id, depth, logic_kind, path = queue.popleft()
        edge = {
            "from": parent_id,
            "to": target_id,
            "depth": depth,
            "logic_kind": logic_kind,
        }
        if target_id in path:
            edges.append({**edge, "status": "cycle_blocked"})
            incomplete = True
            continue
        if target_id in visited:
            edges.append({**edge, "status": "already_included"})
            continue
        try:
            contract = payloads.get_memory_contract(target_id)
        except QuarantinedRecordError:
            edges.append({**edge, "status": "authentication_failed"})
            incomplete = True
            continue
        try:
            details = payloads.get_record_details(target_id)
        except QuarantinedRecordError:
            edges.append({**edge, "status": "authentication_failed"})
            incomplete = True
            continue
        if details is None:
            edges.append({**edge, "status": "missing"})
            incomplete = True
            continue
        if contract.is_expired():
            edges.append({**edge, "status": "expired"})
            incomplete = True
            continue
        effective_at = float(details["effective_at"])
        superseded_at_raw = details["superseded_at"]
        superseded_at = None if superseded_at_raw is None else float(superseded_at_raw)
        temporal_current = details["superseded_by"] is None
        if point_in_time is not None:
            temporal_current = effective_at <= point_in_time and (
                superseded_at is None or point_in_time < superseded_at
            )
            if not temporal_current:
                edges.append({**edge, "status": "not_valid_at_as_of"})
                incomplete = True
                continue
        visited.add(target_id)
        edges.append({**edge, "status": "included"})
        evidence.append(
            {
                "vine_id": target_id,
                "topic": details["topic"],
                "topic_protected": payloads.metadata_protected,
                "payload": details["payload"],
                "depth": depth,
                "temporal_status": (
                    "valid_at_as_of"
                    if point_in_time is not None
                    else ("current" if temporal_current else "superseded")
                ),
                "effective_at": effective_at,
                "superseded_by": details["superseded_by"],
                "superseded_at": superseded_at,
                "query_scored": False,
                "confidence_band": None,
                "confidence_basis": "protected_contextual_link",
                "confidence_indicator": (
                    "Authenticated contextual link; this evidence was not "
                    "independently query-scored."
                ),
                **_public_record_contract(contract, str(details["payload"])),
            }
        )
        if (
            depth < max_depth
            and contract.layer == MemoryLayer.CONTEXTUAL_LOGIC
            and contract.logic_kind is not None
        ):
            next_path = (*path, target_id)
            for related_id in contract.related_ids:
                queue.append(
                    (
                        target_id,
                        related_id,
                        depth + 1,
                        contract.logic_kind.value,
                        next_path,
                    )
                )

    queued_links_omitted = len(queue)
    truncated = queued_links_omitted > 0
    incomplete = incomplete or truncated
    response = {
        "query": root_recall.get("query"),
        "as_of": root_recall.get("as_of"),
        "mode": root_recall.get("mode", "semantic"),
        "degraded": bool(root_recall.get("degraded", False)),
        "semantic_available": root_recall.get("semantic_available", True),
        "logic_roots": roots,
        "root_expansion": root_expansion,
        "evidence": evidence,
        "context_edges": edges,
        "max_depth": max_depth,
        "max_records": max_records,
        "truncated": truncated,
        "queued_links_omitted": queued_links_omitted,
        "incomplete": incomplete,
        "ranking_margin": root_recall.get("ranking_margin"),
        "ranking_ambiguous": bool(root_recall.get("ranking_ambiguous", False)),
        "competing_memory_detected": bool(
            root_recall.get("competing_memory_detected", False)
        ),
        "competing_pair_preserved": bool(
            root_recall.get("competing_pair_preserved", False)
        ),
        "competing_memory_groups": root_recall.get(
            "competing_memory_groups",
            [],
        ),
        "competing_memory_groups_omitted": root_recall.get(
            "competing_memory_groups_omitted",
            0,
        ),
        "gated_count": root_recall.get("gated_count", 0),
        "lifecycle": root_recall.get("lifecycle"),
        "lifecycle_mutated": root_recall.get("lifecycle_mutated", True),
        "context_contract": {
            "query_driven_roots": True,
            "root_confidence_gates_preserved": True,
            "outgoing_links_only": True,
            "evidence_query_scored": False,
            "synthesis_performed": False,
            "layer_relationships_protected": payloads.metadata_protected,
        },
    }
    if "degraded_reason" in root_recall:
        response["degraded_reason"] = root_recall["degraded_reason"]
    if "limitations" in root_recall:
        response["limitations"] = root_recall["limitations"]
    return response


def _public_contract(contract: MemoryLayerContract) -> dict[str, Any]:
    recommendations = contract.recommendations()
    promotion_history = [event.as_dict() for event in contract.promotion_history]
    return {
        "memory_layer": contract.layer.value,
        "provenance": list(contract.provenance),
        "expires_at": contract.expires_at,
        "review_at": contract.review_at,
        "promotion_evidence": (
            None if not promotion_history else promotion_history[-1]
        ),
        "promotion_history": promotion_history,
        "contextual_logic": (
            None
            if contract.logic_kind is None
            else {
                "kind": contract.logic_kind.value,
                "related_ids": list(contract.related_ids),
            }
        ),
        "promotion_recommendation": recommendations["promotion"],
        "archive_recommendation": recommendations["archive"],
        "layer_contract_protected": True,
    }


def _validate_timestamp(value: float | None, name: str) -> float:
    if value is None:
        return time.time()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a finite non-negative timestamp or None")
    result = float(value)
    if not math.isfinite(result) or result < 0.0:
        raise ValueError(f"{name} must be a finite non-negative timestamp")
    return result


def _validate_optional_timestamp(value: float | None, name: str) -> float | None:
    if value is None:
        return None
    return _validate_timestamp(value, name)


def _validate_memory_layers(
    values: list[str] | tuple[str, ...] | None,
) -> tuple[MemoryLayer, ...] | None:
    if values is None:
        return None
    if not isinstance(values, (list, tuple)):
        raise TypeError("layers must be a list of memory-layer names or None")
    if not 1 <= len(values) <= len(MemoryLayer):
        raise ValueError(f"layers must contain between 1 and {len(MemoryLayer)} values")
    parsed: list[MemoryLayer] = []
    for value in values:
        clean = _validate_text(value, "memory layer", 32)
        try:
            parsed.append(MemoryLayer(clean))
        except ValueError as exc:
            raise ValueError(f"unsupported memory layer: {clean}") from exc
    if len(set(parsed)) != len(parsed):
        raise ValueError("layers must not contain duplicate values")
    requested = frozenset(parsed)
    return tuple(layer for layer in MemoryLayer if layer in requested)


def _validate_context_bound(
    value: int,
    name: str,
    maximum: int,
    *,
    minimum: int = 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _validate_vine_ids(
    values: list[str] | tuple[str, ...] | None,
) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        raise TypeError("supersedes must be a list of vine ids")
    if len(values) > 20:
        raise ValueError("supersedes must contain at most 20 vine ids")
    clean = tuple(_validate_text(value, "superseded vine id", 128) for value in values)
    if len(set(clean)) != len(clean):
        raise ValueError("supersedes must not contain duplicate vine ids")
    return clean


def _memory_contract_key(vine_id: str) -> str:
    clean_id = _validate_text(vine_id, "vine_id", 128)
    key = f"{MEMORY_CONTRACT_METADATA_PREFIX}{clean_id}"
    if len(key) > 64:
        raise ValueError("vine_id is too long for protected contract metadata")
    return key


def _record_integrity_key(vine_id: str) -> str:
    clean_id = _validate_text(vine_id, "vine_id", 128)
    key = f"{RECORD_INTEGRITY_METADATA_PREFIX}{clean_id}"
    if len(key) > 64:
        raise ValueError("vine_id is too long for protected integrity metadata")
    return key


def _validate_text(value: str, name: str, max_chars: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    result = value.strip()
    if not result:
        raise ValueError(f"{name} must be non-empty")
    if len(result) > max_chars:
        raise ValueError(f"{name} must be at most {max_chars} characters")
    return result


def _validate_stored_topic(value: object) -> str:
    if not isinstance(value, str):
        raise RuntimeError("stored payload topic is invalid")
    try:
        return _validate_text(value, "stored payload topic", MAX_TOPIC_CHARS)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("stored payload topic is invalid") from exc


def _validate_stored_timestamp(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"stored {name} is invalid")
    timestamp = float(value)
    if not math.isfinite(timestamp) or timestamp < 0.0:
        raise RuntimeError(f"stored {name} is invalid")
    return timestamp


def _validate_profile(value: str) -> str:
    if not isinstance(value, str) or not _PROFILE_PATTERN.fullmatch(value):
        raise ValueError(
            "profile must be 1-64 letters, digits, dots, underscores, or hyphens"
        )
    if value in {".", ".."}:
        raise ValueError("profile must not be a relative path marker")
    return value


def _profile_access_is_owner_only(profile_dir: Path) -> bool:
    """Observe the current profile tree without repairing access controls."""

    try:
        _reject_symlink_components(profile_dir.absolute())
        if os.name == "nt":
            _windows_verify_private_directory(profile_dir)
            return True
        getuid = getattr(os, "getuid", None)
        if not callable(getuid):
            return False
        expected_uid = int(getuid())
        for candidate in (profile_dir, *profile_dir.rglob("*")):
            information = candidate.lstat()
            if (
                stat.S_ISLNK(information.st_mode)
                or int(information.st_uid) != expected_uid
                or stat.S_IMODE(information.st_mode) & 0o077
            ):
                return False
            if candidate.is_dir():
                if not stat.S_ISDIR(information.st_mode):
                    return False
            elif not stat.S_ISREG(information.st_mode):
                return False
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def _secure_directory(path: Path) -> Path:
    candidate = path.absolute()
    _reject_symlink_components(candidate)
    if os.name == "nt":
        return _windows_ensure_private_directory(candidate)
    candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not candidate.is_dir():
        raise ValueError("state directory must be a directory")
    if os.name != "nt":
        candidate.chmod(0o700)
    return candidate


def _reject_symlink_components(path: Path) -> None:
    for candidate in reversed((path, *path.parents)):
        try:
            information = candidate.lstat()
        except FileNotFoundError:
            continue
        reparse_attribute = int(
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
        )
        if stat.S_ISLNK(information.st_mode) or (
            os.name == "nt"
            and bool(
                int(getattr(information, "st_file_attributes", 0)) & reparse_attribute
            )
        ):
            raise ValueError("state paths must not contain symbolic links")


def _secure_regular_file(path: Path) -> None:
    _reject_symlink_components(path.absolute())
    if os.name == "nt":
        _windows_ensure_private_directory(path.parent)
        with _windows_pinned_directory_chain(path.parent):
            try:
                descriptor, state = _windows_create_private_staging(path.absolute())
            except FileExistsError:
                descriptor = _windows_open_private_file(
                    path.absolute(),
                    writable=False,
                    share_write=True,
                )
                state = None
            try:
                _windows_verify_descriptor(
                    descriptor,
                    path.absolute(),
                    expected_payload=None,
                    expected_state=state,
                    expected_security=(
                        None
                        if state is not None
                        else _windows_expected_private_security()
                    ),
                )
            finally:
                os.close(descriptor)
        _windows_verify_private_sqlite_sidecars(path.absolute())
        return
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


def _require_secure_regular_file(path: Path, label: str) -> None:
    try:
        _reject_symlink_components(path.absolute())
    except ValueError as exc:
        raise RuntimeError(f"{label} path must not contain symbolic links") from exc
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} must be an existing regular file")
    if os.name == "nt":
        try:
            with _windows_pinned_directory_chain(path.parent):
                descriptor = _windows_open_private_file(
                    path.absolute(),
                    writable=False,
                    share_write=True,
                )
                try:
                    _windows_verify_descriptor(
                        descriptor,
                        path.absolute(),
                        expected_payload=None,
                        expected_security=_windows_expected_private_security(),
                    )
                finally:
                    os.close(descriptor)
        except OSError as exc:
            raise RuntimeError(f"{label} Windows DACL or identity is unsafe") from exc
    elif stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError(f"{label} must be owner-only")


def _payload_database_version(path: Path) -> int:
    """Read a profile schema version without creating or mutating the database."""

    if not path.exists():
        return 0
    _require_secure_regular_file(path, "payload database")
    _windows_verify_private_sqlite_sidecars(path)
    connection = sqlite3.connect(
        f"{path.resolve().as_uri()}?mode=ro",
        uri=True,
        timeout=5.0,
    )
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        row = connection.execute("PRAGMA user_version").fetchone()
        version = 0 if row is None else int(row[0])
        if version != 0:
            return version

        # Profiles created before schema versioning have user_version=0.  They
        # must stay on the legacy compatibility path until an explicit profile
        # migration; treating them as a fresh scoped-v2 database would mix the
        # new schema and keyring into the existing encrypted payload store.
        columns = tuple(
            (str(item[1]), str(item[2]).upper(), int(item[3]), int(item[5]))
            for item in connection.execute("PRAGMA table_xinfo(payloads)")
            if int(item[6]) == 0
        )
        legacy_columns = (
            ("vine_id", "TEXT", 1, 1),
            ("topic", "TEXT", 1, 0),
            ("nonce", "BLOB", 1, 0),
            ("ciphertext", "BLOB", 1, 0),
            ("content_hash", "TEXT", 1, 0),
            ("created_at", "REAL", 1, 0),
            ("effective_at", "REAL", 0, 0),
            ("superseded_by", "TEXT", 0, 0),
            ("superseded_at", "REAL", 0, 0),
        )
        if columns and columns == legacy_columns[: len(columns)]:
            return LEGACY_PAYLOAD_SCHEMA_VERSION
        object_count_row = connection.execute(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
        ).fetchone()
        if columns or (object_count_row is not None and int(object_count_row[0]) > 0):
            raise RuntimeError("unversioned payload database schema is not recognized")
        return 0
    finally:
        connection.close()


def _load_or_create_key(path: Path) -> bytes:
    _reject_symlink_components(path.absolute())
    if os.name == "nt":
        _windows_ensure_private_directory(path.parent)
        key = AesGcmCryptoShield.generate_key()
        with _windows_pinned_directory_chain(path.parent):
            try:
                descriptor, state = _windows_create_private_staging(path.absolute())
            except FileExistsError:
                return _load_existing_key(path)
            try:
                view = memoryview(key)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("agent key write was incomplete")
                    view = view[written:]
                os.fsync(descriptor)
                _windows_verify_descriptor(
                    descriptor,
                    path.absolute(),
                    expected_payload=key,
                    expected_state=state,
                )
            finally:
                os.close(descriptor)
        return key
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

    return _load_existing_key(path)


def _load_existing_key(path: Path) -> bytes:
    _require_secure_regular_file(path, "agent key")

    descriptor = os.open(path, _binary_noninheritable_read_flags())
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


def _vector_aad(vine_id: str, ordinal: int) -> bytes:
    return (
        b"echo-veil-agent-vector-v1\0"
        + vine_id.encode("utf-8")
        + b"\0"
        + str(ordinal).encode("ascii")
    )
