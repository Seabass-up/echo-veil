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
from collections.abc import Callable
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from numpy.typing import NDArray

from .archive import TransactionalEvictionStore
from .confidence import classify
from .crypto_shield import AesGcmCryptoShield
from .oracle import GenerationGated, Oracle
from .persistence import SQLiteStore
from .proximity import time_decay
from .vectors import cosine_similarity
from .workspace import WorkspaceConfig

DEFAULT_EMBEDDING_DIMENSION = 384
DEFAULT_OLLAMA_EMBEDDING_DIMENSION = 1024
DEFAULT_OLLAMA_MODEL = "qwen3-embedding:latest"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_SEMANTIC_MIN_SCORE = 0.50
DEFAULT_HASHING_MIN_SCORE = 0.35
DEFAULT_CAPACITY = 400
MAX_TOPIC_CHARS = 512
MAX_PAYLOAD_CHARS = 100_000
MAX_QUERY_CHARS = 20_000
MAX_RECALL_RESULTS = 20
MAX_EMBEDDING_RESPONSE_BYTES = 4_194_304
DEFAULT_EMBEDDING_TIMEOUT_SECONDS = 30.0
MAX_MEMORY_PASSAGES = 12
MAX_PASSAGE_CHARS = 1_600
MAX_LEXICAL_FEATURES = 4_096
MAX_QUERY_FEATURES = 256
MAX_RETRIEVAL_CANDIDATES = 900
LEXICAL_BOOST = 0.35
MMR_RELEVANCE_WEIGHT = 0.88
RETRIEVAL_SCHEMA_VERSION = "protected-hybrid-maxsim-v1"
MEMORY_QUERY_INSTRUCTION = (
    "Given a memory recall query, retrieve the stored personal or operational "
    "memory that answers it"
)
_PROFILE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_MODEL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}\Z")
_EMBEDDER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}\Z")
_TOKEN_PATTERN = re.compile(r"[^\W_]+", re.UNICODE)
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
    lexical_score: float
    lifecycle_score: float | None
    best_vector: NDArray[np.float64] | None
    effective_at: float
    superseded_by: str | None
    superseded_at: float | None
    temporal_current: bool


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

    def embed_document(self, text: str) -> NDArray[np.float64]: ...

    def embed_query(self, text: str) -> NDArray[np.float64]: ...


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

    def __call__(self, text: str) -> NDArray[np.float64]:
        return self.embed_document(text)

    def _embed(self, text: str) -> NDArray[np.float64]:
        return self._embed_batch([text])[0]

    def _embed_batch(self, texts: list[str]) -> list[NDArray[np.float64]]:
        response = self._request_json(
            "POST",
            "/api/embed",
            {
                "model": self.model,
                "input": texts,
                "dimensions": self.dimension,
                "truncate": False,
                "keep_alive": "5m",
            },
        )
        embeddings = response.get("embeddings")
        if not isinstance(embeddings, list) or len(embeddings) != len(texts):
            raise RuntimeError("local Ollama returned an invalid embedding response")
        vectors: list[NDArray[np.float64]] = []
        for item in embeddings:
            try:
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

    def _resolve_model(self) -> tuple[str, int]:
        response = self._request_json("GET", "/api/tags")
        models = response.get("models")
        if not isinstance(models, list):
            raise RuntimeError("local Ollama returned an invalid model inventory")
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
            return digest, maximum_dimension
        raise RuntimeError(
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
            encoded = response.read(MAX_EMBEDDING_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise RuntimeError("local Ollama embedding service is unavailable") from exc
        finally:
            connection.close()
        if status != 200:
            raise RuntimeError(
                f"local Ollama embedding request failed with HTTP {status}"
            )
        if len(encoded) > MAX_EMBEDDING_RESPONSE_BYTES:
            raise RuntimeError("local Ollama embedding response exceeded size limit")
        try:
            decoded = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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
        except Exception:
            self._connection.close()
            raise

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
        return str(row[0]), str(row[1])

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
    ) -> None:
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
    ) -> dict[str, _StoredCandidate]:
        query_vector = _normalize_embedding_vector(intent)
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
        cursor = self._connection.execute(
            f"""
            SELECT vine_id, ordinal, nonce, ciphertext, dimension
            FROM memory_vectors
            WHERE vine_id IN ({placeholders})
            ORDER BY vine_id, ordinal
            """,
            parameters,
        )
        for row in cursor:
            vine_id = str(row[0])
            ordinal = int(row[1])
            dimension = int(row[4])
            if dimension != query_vector.size:
                raise RuntimeError("stored retrieval vector dimension mismatch")
            try:
                raw = self._cipher.decrypt(
                    bytes(row[2]),
                    bytes(row[3]),
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

        rows = self._connection.execute(
            f"""
            SELECT vine_id, topic, effective_at, superseded_by, superseded_at
            FROM payloads
            WHERE vine_id IN ({placeholders})
            """,
            parameters,
        ).fetchall()
        candidates: dict[str, _StoredCandidate] = {}
        for row in rows:
            vine_id = str(row[0])
            semantic_entry = semantic.get(vine_id)
            candidates[vine_id] = _StoredCandidate(
                vine_id=vine_id,
                semantic_score=None if semantic_entry is None else semantic_entry[0],
                lexical_score=lexical.get(vine_id, 0.0),
                best_vector=None if semantic_entry is None else semantic_entry[1],
                topic=str(row[1]),
                effective_at=float(row[2]),
                superseded_by=None if row[3] is None else str(row[3]),
                superseded_at=None if row[4] is None else float(row[4]),
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
        return str(row[0]), payload

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
                    topic=str(row[1]),
                    effective_at=float(row[2]),
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

    def _lexical_scores(self, query: str) -> dict[str, float]:
        query_terms = self._term_features(query, MAX_QUERY_FEATURES)
        if not query_terms:
            return {}
        placeholders = ",".join("?" for _ in query_terms)
        rows = self._connection.execute(
            f"""
            SELECT vine_id, term_hash, term_count
            FROM memory_terms
            WHERE term_hash IN ({placeholders})
            """,
            tuple(query_terms),
        ).fetchall()
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
            vine_id: min(
                1.0,
                0.7 * (matched_counts[vine_id] / query_count)
                + 0.3 * (matched_unique[vine_id] / query_unique),
            )
            for vine_id in matched_counts
        }

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
        embed: TextEmbedder | Callable[[str], NDArray[np.float64]] | None = None,
        embedder_id: str | None = None,
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
        self._embedder = _coerce_embedder(embed, embedder_id)
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
            self._bind_embedding_identity()
        except Exception:
            self._payloads.close()
            if self._store is not None:
                self._store.close()
            raise

    def remember(
        self,
        topic: str,
        payload: str,
        *,
        effective_at: float | None = None,
        supersedes: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        clean_topic = _validate_text(topic, "topic", MAX_TOPIC_CHARS)
        clean_payload = _validate_text(payload, "payload", MAX_PAYLOAD_CHARS)
        effective = _validate_timestamp(effective_at, "effective_at")
        superseded_ids = _validate_vine_ids(supersedes)
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

        passages = _memory_passages(clean_topic, clean_payload)
        vectors = _embed_document_batch(self._embedder, passages)
        primary = _normalize_embedding_vector(np.mean(np.stack(vectors), axis=0))
        vine = self.oracle.sprout(clean_topic, primary)
        try:
            self._payloads.put(
                vine.vine_id,
                clean_topic,
                clean_payload,
                content_hash,
                vectors=vectors,
                effective_at=effective,
                supersedes=superseded_ids,
            )
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
            "effective_at": effective,
            "supersedes": list(superseded_ids),
        }

    def recall(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float | None = None,
        allow_inferential: bool = False,
        as_of: float | None = None,
    ) -> dict[str, Any]:
        clean_query = _validate_text(query, "query", MAX_QUERY_CHARS)
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

        intent = self._embedder.embed_query(clean_query)
        lifecycle = self.oracle.observe(intent)
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
        )
        candidates: list[_RankedCandidate] = []
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
            relevance = _hybrid_relevance(semantic_score, item.lexical_score)
            if relevance < threshold:
                continue
            candidates.append(
                _RankedCandidate(
                    vine_id=vine_id,
                    topic=item.topic,
                    source=source,
                    relevance_score=relevance,
                    semantic_score=semantic_score,
                    lexical_score=item.lexical_score,
                    lifecycle_score=lifecycle_score,
                    best_vector=item.best_vector,
                    effective_at=item.effective_at,
                    superseded_by=item.superseded_by,
                    superseded_at=item.superseded_at,
                    temporal_current=temporal_current,
                )
            )

        ranked = _mmr_rank(candidates)

        results: list[dict[str, Any]] = []
        gated_count = 0
        for candidate in ranked:
            vine_id = candidate.vine_id
            score = candidate.relevance_score
            policy = classify(score)
            try:
                self.oracle.check_generation_gate(score, override=allow_inferential)
            except GenerationGated:
                gated_count += 1
                results.append(
                    {
                        "vine_id": vine_id,
                        "topic": candidate.topic,
                        "score": round(score, 6),
                        "semantic_score": _round_optional(candidate.semantic_score),
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
                    }
                )
            else:
                payload = self._payloads.get(vine_id)
                if payload is None:
                    continue
                if candidate.source == "active":
                    self.oracle.reinforce(vine_id)
                results.append(
                    {
                        "vine_id": vine_id,
                        "topic": candidate.topic,
                        "score": round(score, 6),
                        "semantic_score": _round_optional(candidate.semantic_score),
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
                    }
                )
            if len(results) >= top_k:
                break

        return {
            "query": clean_query,
            "as_of": point_in_time,
            "min_score": threshold,
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

    def reindex(self) -> dict[str, Any]:
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
                    try:
                        result = target.remember(
                            record.topic,
                            payload,
                            effective_at=record.effective_at,
                            supersedes=[
                                migrated_ids[prior_id] for prior_id in prior_ids
                            ],
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

    def doctor(self) -> dict[str, Any]:
        capability = self.oracle.capability_report().as_dict()
        key_mode = stat.S_IMODE((self.profile_dir / "agent.key").stat().st_mode)
        indexed_count, unindexed_count = self._payloads.retrieval_index_counts()
        return {
            "adapter_ready": True,
            "mode": "local-staging",
            "profile": self.profile_dir.name,
            "payload_count": len(self._payloads),
            "active_count": len(self.oracle.workspace.vines),
            "archived_count": len(self.oracle.index),
            "key_owner_only": key_mode == 0o600,
            "retrieval": {
                "strategy": RETRIEVAL_SCHEMA_VERSION,
                "protected_multivector_count": indexed_count,
                "unindexed_payload_count": unindexed_count,
                "candidate_limit": MAX_RETRIEVAL_CANDIDATES,
                "lexical_terms": "keyed-hash",
                "diversity_ranking": "topic-aware-mmr",
                "temporal_history": "explicit-supersession",
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
                "Topics remain plaintext metadata in the local owner-only databases.",
                "AES-GCM local staging is not the production enclave profile.",
            ],
        }

    def _managed_exists(self, vine_id: str) -> bool:
        return (
            self.oracle.workspace.get(vine_id) is not None
            or self.oracle.archived_metadata(vine_id) is not None
        )

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


def _round_optional(value: float | None) -> float | None:
    return None if value is None else round(value, 6)


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


def _vector_aad(vine_id: str, ordinal: int) -> bytes:
    return (
        b"echo-veil-agent-vector-v1\0"
        + vine_id.encode("utf-8")
        + b"\0"
        + str(ordinal).encode("ascii")
    )
