from __future__ import annotations

from io import BytesIO
import json
import math
from pathlib import Path
import sqlite3
from typing import Any

import numpy as np
import pytest

import echo_veil.agent_cli as agent_cli
import echo_veil.agent_security as agent_security
from echo_veil.agent_cli import (
    MAX_REQUEST_BYTES,
    McpServer,
    TOOLS,
    _public_error,
    _read_mcp_line,
)
from echo_veil._json import strict_json_loads
import echo_veil.agent_memory as agent_memory
from echo_veil.agent_memory import (
    AgentMemory,
    AlwaysAvailableMemory,
    DEFAULT_SEMANTIC_MIN_SCORE,
    EmbeddingUnavailable,
    HashingTextEmbedder,
    OllamaTextEmbedder,
)


class _SemanticTestEmbedder:
    identity = "test:semantic:v1:dimension:32"
    name = "test"
    model = "semantic-v1"
    dimension = 32
    semantic = True
    default_min_score = DEFAULT_SEMANTIC_MIN_SCORE

    def embed_document(self, _text: str) -> np.ndarray[Any, np.dtype[np.float64]]:
        vector = np.zeros(self.dimension)
        vector[0] = 1.0
        return vector

    def embed_query(self, text: str) -> np.ndarray[Any, np.dtype[np.float64]]:
        similarity = 0.10 if "unrelated" in text else 0.55
        vector = np.zeros(self.dimension)
        vector[0] = similarity
        vector[1] = math.sqrt(1.0 - similarity**2)
        return vector


def test_hashing_embedder_is_stable_and_keyword_oriented() -> None:
    embed = HashingTextEmbedder(128)

    first = embed("Harbor labor rate estimate")
    repeated = embed("Harbor labor rate estimate")
    related = embed("labor rate")
    unrelated = embed("school pickup schedule")

    assert np.array_equal(first, repeated)
    assert float(first @ related) > float(first @ unrelated)
    assert np.linalg.norm(first) == pytest.approx(1.0)


def test_semantic_embedder_uses_calibrated_default_and_rejects_distractor(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        memory.remember("deployment location", "Current project documents live here.")

        paraphrase = memory.recall("Where should company files be kept?")
        distractor = memory.recall("unrelated purple animal phrase")

    assert paraphrase["min_score"] == DEFAULT_SEMANTIC_MIN_SCORE
    assert paraphrase["results"][0]["payload"] == (
        "Current project documents live here."
    )
    assert distractor["results"] == []


def test_semantic_answerability_rejects_same_subject_absent_fact(
    tmp_path: Path,
) -> None:
    class AnswerabilityEmbedder(_SemanticTestEmbedder):
        identity = "test:answerability:v1:dimension:32"

        def embed_query(self, _text: str) -> np.ndarray[Any, np.dtype[np.float64]]:
            vector = np.zeros(self.dimension)
            vector[0] = 1.0
            return vector

        def embed_answerability_query(
            self, text: str
        ) -> np.ndarray[Any, np.dtype[np.float64]]:
            vector = np.zeros(self.dimension)
            vector[1 if "passport" in text else 0] = 1.0
            return vector

    with AgentMemory(tmp_path, embed=AnswerabilityEmbedder()) as memory:
        memory.remember(
            "Taylor family",
            "Taylor's children are Morgan, Riley, and Casey.",
        )

        answerable = memory.recall("Who are Taylor's children?")
        absent = memory.recall("What is Taylor's passport number?")
        report = memory.doctor()

    assert answerable["results"][0]["answerability_score"] == 1.0
    assert absent["results"] == []
    assert absent["answerability_rejected_count"] == 1
    assert report["retrieval"]["answerability_gate"] == "semantic-predicate-v1"


def test_close_semantic_results_are_reported_as_ranking_ambiguity(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        memory.remember("first policy", "The first policy applies.")
        memory.remember("second policy", "The second policy applies.")

        recalled = memory.recall("Which rule applies?", top_k=2)

    assert [item["rank"] for item in recalled["results"]] == [1, 2]
    assert recalled["ranking_margin"] == 0.0
    assert recalled["ranking_ambiguous"] is True


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("What is Taylor's passport number?", "What is passport number?"),
        ("Which team does Taylor support?", "Which team does support?"),
        ("Does the family have a dog?", "is there a dog?"),
        (
            "How should J-space ideas be treated?",
            "How should J-space ideas be treated?",
        ),
    ],
)
def test_predicate_query_masks_subject_without_domain_rules(
    query: str,
    expected: str,
) -> None:
    assert agent_memory._predicate_query(query) == expected


def test_profile_rejects_embedding_identity_changes(tmp_path: Path) -> None:
    with AgentMemory(tmp_path) as memory:
        memory.remember("stable model", "This profile uses hashing vectors.")

    with pytest.raises(RuntimeError, match="embedding identity"):
        AgentMemory(tmp_path, embed=_SemanticTestEmbedder())


def test_profile_rejects_changed_model_digest(tmp_path: Path) -> None:
    class DigestEmbedder(_SemanticTestEmbedder):
        def __init__(self, digest: str) -> None:
            self.identity = (
                f"ollama:qwen3-embedding:latest@sha256:{digest}:dimension:32"
            )

    with AgentMemory(tmp_path, embed=DigestEmbedder("a" * 64)) as memory:
        memory.remember("digest binding", "This profile binds its model artifact.")

    with pytest.raises(RuntimeError, match="embedding identity"):
        AgentMemory(tmp_path, embed=DigestEmbedder("b" * 64))


def test_profile_writer_lease_serializes_fresh_process_snapshots(
    tmp_path: Path,
) -> None:
    first = AgentMemory(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="another writer"):
            AgentMemory(tmp_path, profile_lock_timeout_seconds=0.01)
    finally:
        first.close()

    with AgentMemory(tmp_path, profile_lock_timeout_seconds=0.01) as reopened:
        assert reopened.doctor()["writer_serialization"] == "profile-sqlite-lease"


def test_sqlite_lock_detection_supports_legacy_and_extended_errors() -> None:
    legacy = sqlite3.OperationalError("database is locked")
    extended = sqlite3.OperationalError("synthetic extended busy result")
    extended.sqlite_errorcode = 773  # type: ignore[attr-defined]

    assert agent_memory._is_sqlite_lock_error(legacy) is True
    assert agent_memory._is_sqlite_lock_error(extended) is True
    assert (
        agent_memory._is_sqlite_lock_error(
            sqlite3.OperationalError("database disk image is malformed")
        )
        is False
    )


def test_profile_startup_repairs_lifecycle_record_without_payload(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path) as memory:
        orphan = memory.oracle.sprout(
            "interrupted remember",
            HashingTextEmbedder()("interrupted remember"),
        )
        assert memory.oracle.workspace.get(orphan.vine_id) is not None

    with AgentMemory(tmp_path) as recovered:
        doctor = recovered.doctor()
        assert doctor["recovered_incomplete_lifecycle_records"] == 1
        assert recovered.oracle.workspace.get(orphan.vine_id) is None


def test_profile_startup_preserves_and_blocks_payload_without_lifecycle(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path) as memory:
        created = memory.remember(
            "preserve me", "Encrypted payload must not be deleted."
        )
        assert memory.oracle.forget(str(created["vine_id"])) is True

    with pytest.raises(RuntimeError, match="automatic deletion is refused"):
        AgentMemory(tmp_path)


def test_state_path_rejects_symbolic_link_components(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(ValueError, match="symbolic links"):
        AgentMemory(linked)


def test_payload_database_rejects_unexpected_schema_objects(tmp_path: Path) -> None:
    with AgentMemory(tmp_path):
        pass
    path = tmp_path / "default" / "payloads.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TRIGGER injected_trigger BEFORE DELETE ON payloads "
        "BEGIN SELECT RAISE(ABORT, 'blocked'); END"
    )
    connection.close()

    with pytest.raises(RuntimeError, match="schema validation"):
        AgentMemory(tmp_path)


def test_unversioned_legacy_payload_database_uses_compatibility_path(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "default"
    profile.mkdir(mode=0o700)
    key = b"k" * 32
    key_path = profile / "agent.key"
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    store = agent_memory._LegacyEncryptedPayloadStore(
        profile / "payloads.db",
        key,
    )
    store.close()
    connection = sqlite3.connect(profile / "payloads.db")
    try:
        connection.execute("PRAGMA user_version = 0")
    finally:
        connection.close()

    with AgentMemory(tmp_path) as memory:
        report = memory.doctor()

    assert report["security_schema"] == "legacy-v1"
    connection = sqlite3.connect(profile / "payloads.db")
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
    finally:
        connection.close()


def test_payload_database_rejects_foreign_key_orphans(tmp_path: Path) -> None:
    with AgentMemory(tmp_path):
        pass
    path = tmp_path / "default" / "payloads.db"
    manifest = json.loads(
        (tmp_path / "default" / "keyring.json").read_text(encoding="utf-8")
    )
    connection = sqlite3.connect(path)
    connection.execute(
        """
        INSERT INTO memory_terms(vine_id, term_hash, term_count, key_id)
        VALUES (?, ?, ?, ?)
        """,
        (
            "missing-vine",
            b"synthetic-hash!!",
            1,
            manifest["active_key_id"],
        ),
    )
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="foreign-key integrity"):
        AgentMemory(tmp_path)


def test_ollama_embedder_is_loopback_only_digest_bound_and_instruction_aware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, str, bytes | None]] = []
    digest = "a" * 64

    class Response:
        status = 200

        def __init__(self, body: object) -> None:
            self._body = json.dumps(body).encode()

        def read(self, _limit: int) -> bytes:
            return self._body

        def getheader(self, name: str, default: str | None = None) -> str | None:
            if name == "Content-Type":
                return "application/json"
            if name == "Content-Length":
                return str(len(self._body))
            return default

    class Connection:
        def __init__(self, _host: str, _port: int, *, timeout: float) -> None:
            assert timeout == 2.0

        def request(
            self,
            method: str,
            path: str,
            body: bytes | None = None,
            headers: object | None = None,
        ) -> None:
            del headers
            requests.append((method, path, body))

        def getresponse(self) -> Response:
            if requests[-1][1] == "/api/tags":
                return Response(
                    {
                        "models": [
                            {
                                "name": "qwen3-embedding:latest",
                                "digest": digest,
                                "details": {"embedding_length": 4096},
                            }
                        ]
                    }
                )
            vector = [0.0] * 32
            vector[0] = 2.0
            body = json.loads(requests[-1][2] or b"{}")
            return Response({"embeddings": [vector for _ in body["input"]]})

        def close(self) -> None:
            return None

    monkeypatch.setattr(agent_memory.http.client, "HTTPConnection", Connection)
    embedder = OllamaTextEmbedder(dimension=32, timeout_seconds=2)
    document = embedder.embed_document("The launch code is blue.")
    query, answerability = embedder.embed_retrieval_queries(
        "What is Taylor's passport number?"
    )

    assert f"@sha256:{digest}" in embedder.identity
    assert np.linalg.norm(document) == pytest.approx(1.0)
    assert np.linalg.norm(query) == pytest.approx(1.0)
    assert np.linalg.norm(answerability) == pytest.approx(1.0)
    document_body = json.loads(requests[-3][2] or b"{}")
    query_body = json.loads(requests[-1][2] or b"{}")
    assert document_body["input"] == ["The launch code is blue."]
    assert query_body["input"][0].startswith("Instruct: ")
    assert "Taylor" not in query_body["input"][1]
    assert query_body["input"][1].endswith("Query: What is passport number?")
    assert query_body["input"][0].endswith("Query: What is Taylor's passport number?")

    with pytest.raises(ValueError, match="loopback IP literal"):
        OllamaTextEmbedder(base_url="http://localhost:11434", dimension=32)
    with pytest.raises(ValueError, match="loopback IP literal"):
        OllamaTextEmbedder(base_url="http://192.0.2.1:11434", dimension=32)


def test_ollama_embedder_rechecks_mutable_model_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digests = ["a" * 64, "b" * 64]

    class Response:
        status = 200

        def getheader(self, name: str, default: str | None = None) -> str | None:
            if name == "Content-Type":
                return "application/json"
            return default

        def read(self, _limit: int) -> bytes:
            return json.dumps(
                {
                    "models": [
                        {
                            "name": "qwen3-embedding:latest",
                            "digest": digests.pop(0),
                            "details": {"embedding_length": 4096},
                        }
                    ]
                }
            ).encode()

    class Connection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        def request(self, *_args: object, **_kwargs: object) -> None:
            return None

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            return None

    monkeypatch.setattr(agent_memory.http.client, "HTTPConnection", Connection)
    embedder = OllamaTextEmbedder(dimension=32)

    with pytest.raises(RuntimeError, match="identity changed"):
        embedder.embed_query("Where is the current runbook?")


def test_ollama_unavailable_fails_closed_without_hashing_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Connection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        def request(self, *_args: object, **_kwargs: object) -> None:
            raise ConnectionRefusedError("synthetic outage")

        def close(self) -> None:
            return None

    monkeypatch.setattr(agent_memory.http.client, "HTTPConnection", Connection)
    with pytest.raises(RuntimeError, match="service is unavailable"):
        OllamaTextEmbedder(dimension=32)


def test_always_available_layer_is_read_only_explicit_and_conservative(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        created = memory.remember(
            "deployment recovery procedure",
            "Use the opal harbor recovery procedure during a deployment outage.",
        )
        memory.remember(
            "Taylor family",
            "Taylor's children are Morgan, Riley, and Casey.",
        )
    payload_database = tmp_path / "default" / "payloads.db"
    before = payload_database.read_bytes()
    lifecycle_database = tmp_path / "default" / "echo-veil.db"
    lifecycle_before = lifecycle_database.read_bytes()

    with AlwaysAvailableMemory(
        tmp_path,
        reason="synthetic_embedding_outage",
    ) as available:
        recalled = available.recall("deployment recovery procedure opal harbor outage")
        paraphrase = available.recall("How should we get the service working again?")
        absent = available.recall("What is Taylor's passport number?")
        doctor = available.doctor()

        assert recalled["results"][0]["vine_id"] == created["vine_id"]
        assert recalled["degraded"] is True
        assert recalled["semantic_available"] is False
        assert recalled["lifecycle_mutated"] is False
        assert recalled["results"][0]["confidence_band"] == ("fragmented_synthesis")
        assert recalled["results"][0]["score"] < 0.70
        assert recalled["results"][0]["availability_score"] >= 0.45
        assert paraphrase["results"] == []
        assert absent["results"] == []
        assert doctor["mode"] == "always-available-read-only"
        assert doctor["writes_available"] is False
        with pytest.raises(ValueError, match="safe default"):
            available.recall("deployment recovery", min_score=0.44)
        with pytest.raises(RuntimeError, match="read-only"):
            available.remember("new", "not allowed")
        with pytest.raises(RuntimeError, match="read-only"):
            available.forget(str(created["vine_id"]))
        with pytest.raises(RuntimeError, match="read-only"):
            available.reindex()

    assert payload_database.read_bytes() == before
    assert lifecycle_database.read_bytes() == lifecycle_before


def test_runtime_embedding_outage_transitions_to_read_only_availability(
    tmp_path: Path,
) -> None:
    class RuntimeOutageEmbedder(_SemanticTestEmbedder):
        identity = "test:runtime-outage:v1:dimension:32"

        def __init__(self) -> None:
            self.available = True

        def embed_query(self, text: str) -> np.ndarray[Any, np.dtype[np.float64]]:
            if not self.available:
                raise EmbeddingUnavailable("synthetic runtime outage")
            return super().embed_query(text)

    embedder = RuntimeOutageEmbedder()
    primary = AgentMemory(tmp_path, embed=embedder)
    memory = agent_cli._RuntimeAvailabilityMemory(  # noqa: SLF001 - failover contract
        primary,
        tmp_path,
        "default",
    )
    try:
        memory.remember(
            "opal harbor recovery procedure",
            "Use the opal harbor recovery procedure during a deployment outage.",
        )
        embedder.available = False

        recalled = memory.recall("opal harbor recovery procedure", top_k=2)
        doctor = memory.doctor()

        assert recalled["degraded"] is True
        assert recalled["semantic_available"] is False
        assert recalled["lifecycle_mutated"] is False
        assert recalled["results"][0]["topic"] == "opal harbor recovery procedure"
        assert doctor["runtime_failover_active"] is True
        with pytest.raises(RuntimeError, match="read-only"):
            memory.remember("blocked", "Writes stay blocked during the outage.")
    finally:
        memory.close()


def test_cli_uses_always_available_layer_only_for_embedding_unavailability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with AgentMemory(
        tmp_path, profile="semantic", embed=_SemanticTestEmbedder()
    ) as memory:
        memory.remember("offline runbook", "Use the offline runbook during outage.")

    def unavailable(_args: object) -> object:
        raise EmbeddingUnavailable("synthetic outage")

    observed: dict[str, object] = {}

    def run_rpc(memory: object) -> int:
        observed["memory"] = memory
        return 0

    monkeypatch.setattr(agent_cli, "_build_embedder", unavailable)
    monkeypatch.setattr(agent_cli, "run_rpc", run_rpc)

    result = agent_cli.main(
        [
            "--state-dir",
            str(tmp_path),
            "--profile",
            "semantic",
            "--embedder",
            "ollama",
            "rpc",
        ]
    )

    assert result == 0
    assert isinstance(observed["memory"], AlwaysAvailableMemory)

    disabled = agent_cli.main(
        [
            "--state-dir",
            str(tmp_path),
            "--profile",
            "semantic",
            "--embedder",
            "ollama",
            "--no-availability-layer",
            "rpc",
        ]
    )
    assert disabled == 1


def test_agent_memory_persists_deduplicates_recalls_and_forgets(tmp_path: Path) -> None:
    topic = "Harbor service estimate labor rate"
    payload = "The synthetic example labor rate is 137 dollars per hour."
    query = f"{topic}\n{payload}"

    with AgentMemory(tmp_path) as memory:
        created = memory.remember(topic, payload)
        duplicate = memory.remember(topic, payload)
        recalled = memory.recall(query)

        assert created["created"] is True
        assert duplicate == {
            "vine_id": created["vine_id"],
            "topic": topic,
            "created": False,
            "duplicate": True,
        }
        assert recalled["results"][0]["payload"] == payload
        assert recalled["results"][0]["gated"] is False
        assert recalled["results"][0]["confidence_band"] == ("solid_vine_integration")

    assert payload.encode() not in (tmp_path / "default" / "payloads.db").read_bytes()

    with AgentMemory(tmp_path) as restored:
        recalled = restored.recall(query)
        assert recalled["results"][0]["vine_id"] == created["vine_id"]
        assert recalled["results"][0]["payload"] == payload

        forgotten = restored.forget(str(created["vine_id"]))
        assert forgotten["forgotten"] is True
        assert restored.recall(query)["results"] == []
        assert restored.forget(str(created["vine_id"]))["forgotten"] is False


def test_supersession_preserves_history_ranks_current_and_restores_predecessor(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        old = memory.remember(
            "deployment region",
            "The service deploys in the west region.",
            effective_at=100.0,
        )
        current = memory.remember(
            "deployment region",
            "The service now deploys in the central region.",
            effective_at=200.0,
            supersedes=[str(old["vine_id"])],
        )

        results = memory.recall("Where does the service deploy?", top_k=2)["results"]
        assert [item["vine_id"] for item in results] == [
            current["vine_id"],
            old["vine_id"],
        ]
        assert [item["temporal_status"] for item in results] == [
            "current",
            "superseded",
        ]

        historical = memory.recall(
            "Where did the service deploy?", top_k=1, as_of=150.0
        )
        assert historical["results"][0]["vine_id"] == old["vine_id"]
        assert historical["results"][0]["temporal_status"] == "valid_at_as_of"

        memory.forget(str(current["vine_id"]))
        restored = memory.recall("Where does the service deploy?", top_k=1)
        assert restored["results"][0]["vine_id"] == old["vine_id"]
        assert restored["results"][0]["temporal_status"] == "current"


def test_reindex_repairs_missing_protected_retrieval_data(tmp_path: Path) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        memory.remember("runbook", "Use the blue recovery runbook.")
        database = sqlite3.connect(tmp_path / "default" / "payloads.db")
        try:
            database.execute("DELETE FROM memory_vectors")
            database.commit()
        finally:
            database.close()

        assert memory.doctor()["retrieval"]["unindexed_payload_count"] == 1
        report = memory.reindex()
        assert report["reindexed"] == 1
        assert memory.doctor()["retrieval"]["unindexed_payload_count"] == 0


def test_long_memory_uses_encrypted_multivectors_and_keyed_terms(
    tmp_path: Path,
) -> None:
    payload = ("Routine synthetic filler sentence. " * 130) + (
        "The emergency bypass codename is opal-harbor-773."
    )
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        memory.remember("recovery handbook", payload)
        report = memory.doctor()

    database_bytes = (tmp_path / "default" / "payloads.db").read_bytes()
    database = sqlite3.connect(tmp_path / "default" / "payloads.db")
    try:
        vector_count = int(
            database.execute("SELECT COUNT(*) FROM memory_vectors").fetchone()[0]
        )
        term_count = int(
            database.execute("SELECT COUNT(*) FROM memory_terms").fetchone()[0]
        )
    finally:
        database.close()

    assert vector_count > 1
    assert term_count > 0
    assert report["retrieval"]["protected_multivector_count"] == 1
    assert b"opal-harbor-773" not in database_bytes
    assert payload.encode() not in database_bytes


def test_profile_migration_reembeds_without_plaintext_export_and_keeps_history(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, profile="hashing") as source:
        old = source.remember(
            "service region", "The region was west.", effective_at=100.0
        )
        source.remember(
            "service region",
            "The region is now central.",
            effective_at=200.0,
            supersedes=[str(old["vine_id"])],
        )
        with AgentMemory(
            tmp_path, profile="semantic", embed=_SemanticTestEmbedder()
        ) as target:
            with pytest.raises(ValueError, match="confirm=true"):
                source.migrate_to(target)
            report = source.migrate_to(target, confirm=True)
            current = target.recall("Where is the service region?", top_k=2)

            assert report["migrated"] == 2
            assert report["history_links"] == 1
            assert report["lifecycle_state_preserved"] is False
            assert report["plaintext_export_created"] is False
            assert [item["temporal_status"] for item in current["results"]] == [
                "current",
                "superseded",
            ]
            with pytest.raises(ValueError, match="target profile must be empty"):
                source.migrate_to(target, confirm=True)


def test_agent_memory_doctor_reports_local_boundary(tmp_path: Path) -> None:
    with AgentMemory(tmp_path) as memory:
        report = memory.doctor()

    assert report["adapter_ready"] is True
    assert report["mode"] == "local-staging"
    assert report["profile"] == "default"
    assert "profile_dir" not in report
    assert report["key_owner_only"] is True
    assert report["security_schema"] == "scoped-v2"
    assert report["scope_bound"] is True
    assert report["readiness"] == {
        "installed": True,
        "enabled": True,
        "crypto_initialized": True,
        "write_wired": True,
        "index_wired": True,
        "retrieval_wired": True,
        "persistence_wired": True,
        "restart_restored": True,
        "rotation_ready": True,
        "healthy": True,
    }
    assert report["quarantined_records"] == 0
    assert report["local_protection_ready"] is True
    assert report["production_ready"] is False
    assert report["store_permissions"] == "valid"
    assert report["reconciliation_backlog"] == 0
    assert report["failed_decryptions"] == 0
    assert report["retrieval"]["answerability_gate"] == "unavailable"
    assert report["retrieval"]["answerability_min_score"] is None
    assert report["retrieval"]["metadata"] == "opaque-authenticated"
    assert report["capability_report"]["overall_status"] == "blocked"
    assert any("not the production enclave" in item for item in report["limitations"])


def test_scoped_profile_encrypts_content_topics_vectors_and_scope_binding(
    tmp_path: Path,
) -> None:
    topic = "confidential project codename cedar"
    payload = "The private recovery phrase is cobalt lantern 849."
    with AgentMemory(tmp_path, scope="workspace:synthetic-alpha") as memory:
        created = memory.remember(topic, payload)
        report = memory.doctor()

    profile = tmp_path / "default"
    for path in (profile / "payloads.db", profile / "echo-veil.db"):
        persisted = path.read_bytes()
        assert topic.encode() not in persisted
        assert payload.encode() not in persisted
        assert str(created["vine_id"]).encode() in persisted
    assert report["key_id"].startswith("ev-")
    assert "scope_id" not in report
    assert "profile_dir" not in report

    with pytest.raises(PermissionError, match="scope"):
        AgentMemory(tmp_path, scope="workspace:synthetic-beta")


def test_corrupt_record_is_quarantined_without_hiding_healthy_records(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, scope="workspace:quarantine") as memory:
        corrupt = memory.remember("alpha recovery", "Use the alpha recovery path.")
        healthy = memory.remember("beta recovery", "Use the beta recovery path.")

    connection = sqlite3.connect(tmp_path / "default" / "payloads.db")
    try:
        connection.execute(
            """
            UPDATE payloads
            SET ciphertext = substr(ciphertext, 1, length(ciphertext) - 1) || x'00'
            WHERE vine_id = ?
            """,
            (corrupt["vine_id"],),
        )
        connection.commit()
    finally:
        connection.close()

    with AgentMemory(tmp_path, scope="workspace:quarantine") as memory:
        assert memory.recall("alpha recovery path")["results"] == []
        recalled = memory.recall("beta recovery path")
        report = memory.doctor()

    assert recalled["results"][0]["vine_id"] == healthy["vine_id"]
    assert recalled["results"][0]["payload"] == "Use the beta recovery path."
    assert report["quarantined_records"] == 1
    assert report["readiness"]["healthy"] is False
    assert "ciphertext" not in json.dumps(report).casefold()


def test_crafted_cross_scope_metadata_quarantines_only_the_bad_record(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, scope="workspace:metadata") as memory:
        poisoned = memory.remember("alpha scope", "Alpha remains isolated.")
        healthy = memory.remember("beta scope", "Beta remains available.")

    connection = sqlite3.connect(tmp_path / "default" / "payloads.db")
    try:
        connection.execute(
            "UPDATE payloads SET scope_id = ? WHERE vine_id = ?",
            ("scope-00000000000000000000000000000000", poisoned["vine_id"]),
        )
        connection.commit()
    finally:
        connection.close()

    with AgentMemory(tmp_path, scope="workspace:metadata") as memory:
        assert memory.recall("alpha scope")["results"] == []
        recalled = memory.recall("beta scope available")
        report = memory.doctor()

    assert recalled["results"][0]["vine_id"] == healthy["vine_id"]
    assert report["quarantined_records"] == 1
    assert report["production_ready"] is False


def test_cross_table_nonce_reuse_stops_profile_without_exposing_content(
    tmp_path: Path,
) -> None:
    secret = "Nonce reuse must never reveal this synthetic secret."
    with AgentMemory(tmp_path, scope="workspace:nonce") as memory:
        created = memory.remember("nonce test", secret)

    connection = sqlite3.connect(tmp_path / "default" / "payloads.db")
    try:
        payload_nonce = connection.execute(
            "SELECT nonce FROM payloads WHERE vine_id = ?",
            (created["vine_id"],),
        ).fetchone()[0]
        connection.execute(
            "UPDATE memory_vectors SET nonce = ? WHERE vine_id = ? AND ordinal = 0",
            (payload_nonce, created["vine_id"]),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="reused AES-GCM nonce") as failure:
        AgentMemory(tmp_path, scope="workspace:nonce")
    assert secret not in str(failure.value)


def test_security_files_with_broad_permissions_fail_closed(tmp_path: Path) -> None:
    if agent_security.os.name == "nt":
        pytest.skip("POSIX permission bits are unavailable")
    with AgentMemory(tmp_path, scope="workspace:permissions") as memory:
        key_id = memory.doctor()["key_id"]
    key_path = tmp_path / "default" / "keys" / f"{key_id}.key"
    key_path.chmod(0o644)
    try:
        with pytest.raises(RuntimeError, match="permissions"):
            AgentMemory(tmp_path, scope="workspace:permissions")
    finally:
        key_path.chmod(0o600)


def test_failed_rotation_manifest_commit_keeps_old_key_and_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with AgentMemory(tmp_path, scope="workspace:rotation-commit") as memory:
        memory.remember("rotation commit", "The old key remains usable.")
        old_key_id = memory.doctor()["key_id"]
        key_directory = tmp_path / "default" / "keys"
        original_key_files = {path.name for path in key_directory.iterdir()}
        original_write = agent_security._atomic_write_json

        def fail_manifest_write(_path: Path, _payload: dict[str, Any]) -> None:
            raise OSError("synthetic manifest commit failure")

        monkeypatch.setattr(
            agent_security,
            "_atomic_write_json",
            fail_manifest_write,
        )
        with pytest.raises(OSError, match="manifest commit"):
            memory.rotate_key(confirm=True)
        assert memory.doctor()["key_id"] == old_key_id
        assert {path.name for path in key_directory.iterdir()} == original_key_files

        monkeypatch.setattr(agent_security, "_atomic_write_json", original_write)
        resumed = memory.rotate_key(confirm=True, batch_size=100)
        assert resumed["state"] == "verified"
        assert memory.recall("rotation commit")["results"][0]["payload"] == (
            "The old key remains usable."
        )


def test_key_rotation_is_resumable_restart_safe_and_explicitly_retired(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, scope="workspace:rotation") as memory:
        created = [
            memory.remember(f"rotation topic {index}", f"rotation payload {index}")
            for index in range(3)
        ]
        first = memory.rotate_key(confirm=True, batch_size=1)
        assert first["state"] == "migrating"
        assert first["remaining_key_references"] > 0

    with AgentMemory(tmp_path, scope="workspace:rotation") as memory:
        second = memory.rotate_key(confirm=True, batch_size=1)
        third = memory.rotate_key(confirm=True, batch_size=1)
        assert second["state"] in {"migrating", "verified"}
        assert third["state"] == "verified"
        for index, record in enumerate(created):
            recalled = memory.recall(f"rotation topic {index} payload {index}")
            assert recalled["results"][0]["vine_id"] == record["vine_id"]
        retired = memory.retire_previous_key(confirm_backups_accounted_for=True)
        assert retired["physical_erasure_guaranteed"] is False

    with AgentMemory(tmp_path, scope="workspace:rotation") as memory:
        assert memory.doctor()["rotation"]["state"] == "idle"
        assert (
            memory.recall("rotation topic 2 payload 2")["results"][0]["payload"]
            == "rotation payload 2"
        )


def test_missing_profile_key_fails_closed_instead_of_resetting_store(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, scope="workspace:lost-key") as memory:
        memory.remember("lost key record", "This record must never look absent.")
        key_id = memory.doctor()["key_id"]
    key_path = tmp_path / "default" / "keys" / f"{key_id}.key"
    missing_path = key_path.with_suffix(".missing")
    key_path.rename(missing_path)
    try:
        with pytest.raises(RuntimeError, match="key"):
            AgentMemory(tmp_path, scope="workspace:lost-key")
    finally:
        missing_path.rename(key_path)

    with AgentMemory(tmp_path, scope="workspace:lost-key") as memory:
        assert memory.recall("lost key record")["results"][0]["payload"] == (
            "This record must never look absent."
        )


def test_agent_memory_recalls_an_evicted_payload_from_cold_index(
    tmp_path: Path,
) -> None:
    first_topic = "Harbor labor estimate"
    first_payload = "Harbor estimate uses a synthetic 137 dollar labor rate."
    second_topic = "School pickup schedule"
    second_payload = "School pickup is at 3 PM by the west entrance."

    with AgentMemory(tmp_path, capacity=1) as memory:
        memory.remember(first_topic, first_payload)
        archived = memory.remember(second_topic, second_payload)

        memory.recall(f"{first_topic}\n{first_payload}")
        recalled = memory.recall(f"{second_topic}\n{second_payload}")

    assert recalled["results"][0]["vine_id"] == archived["vine_id"]
    assert recalled["results"][0]["source"] == "archive"
    assert recalled["results"][0]["payload"] == second_payload


def test_agent_memory_rejects_profile_path_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="profile"):
        AgentMemory(tmp_path, profile="../escape")


def test_mcp_server_exposes_and_executes_echo_veil_tools(tmp_path: Path) -> None:
    assert [tool["name"] for tool in TOOLS] == [
        "echo_veil_remember",
        "echo_veil_recall",
        "echo_veil_forget",
        "echo_veil_doctor",
        "echo_veil_reindex",
        "echo_veil_rotate_key",
        "echo_veil_retire_key",
    ]

    with AgentMemory(tmp_path) as memory:
        server = McpServer(memory)
        initialized = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "1900-01-01"},
            }
        )
        listed = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        remembered = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "echo_veil_remember",
                    "arguments": {
                        "topic": "school pickup schedule",
                        "payload": "School pickup is at 3 PM.",
                    },
                },
            }
        )
        refused_reindex = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "echo_veil_reindex",
                    "arguments": {"confirm": False},
                },
            }
        )
        reindexed = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "echo_veil_reindex",
                    "arguments": {"confirm": True},
                },
            }
        )

    assert initialized is not None
    assert initialized["result"]["protocolVersion"] == "2025-11-25"
    assert initialized["result"]["serverInfo"]["name"] == "echo-veil"
    assert listed is not None
    assert len(listed["result"]["tools"]) == 7
    recall_tool = next(
        tool for tool in listed["result"]["tools"] if tool["name"] == "echo_veil_recall"
    )
    assert recall_tool["inputSchema"]["properties"]["top_k"]["minimum"] == 2
    assert "not semantic or authoritative" in initialized["result"]["instructions"]
    assert remembered is not None
    assert remembered["result"]["isError"] is False
    assert remembered["result"]["structuredContent"]["created"] is True
    assert refused_reindex is not None
    assert refused_reindex["result"]["isError"] is True
    assert reindexed is not None
    assert reindexed["result"]["isError"] is False
    assert reindexed["result"]["structuredContent"]["reindexed"] == 1


def test_rpc_recall_preserves_ambiguous_pair_when_one_result_requested(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        memory.remember("first policy", "The first policy applies.")
        memory.remember("second policy", "The second policy applies.")

        recalled = agent_cli.dispatch(
            memory,
            "recall",
            {"query": "Which rule applies?", "top_k": 1},
        )

    assert len(recalled["results"]) == 2
    assert recalled["ranking_ambiguous"] is True
    assert recalled["requested_top_k"] == 1
    assert recalled["effective_top_k"] == 2
    assert recalled["ambiguity_candidates_preserved"] is True


def test_mcp_line_reader_bounds_and_drains_oversized_requests() -> None:
    stream = BytesIO(b"x" * (MAX_REQUEST_BYTES + 50) + b"\n{}\n")

    first, oversized = _read_mcp_line(stream)
    second, second_oversized = _read_mcp_line(stream)

    assert len(first) == MAX_REQUEST_BYTES + 1
    assert oversized is True
    assert second == b"{}\n"
    assert second_oversized is False


def test_protocol_json_rejects_duplicates_nonfinite_and_wrong_rpc_version(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="duplicate"):
        strict_json_loads(b'{"action":"doctor","action":"forget"}')
    with pytest.raises(ValueError, match="non-finite"):
        strict_json_loads(b'{"score":NaN}')
    with pytest.raises(ValueError, match="non-finite"):
        strict_json_loads(b'{"score":1e9999}')

    with AgentMemory(tmp_path) as memory:
        response = McpServer(memory).handle(
            {"jsonrpc": "1.0", "id": 1, "method": "tools/list"}
        )
    assert response is not None
    assert response["error"]["code"] == -32600


def test_public_adapter_errors_redact_paths_secrets_and_email() -> None:
    payload = _public_error(
        RuntimeError(
            "failed at /sensitive/location/file token=top-secret "
            "api_key=another-secret Authorization: Bearer third-secret "
            "operator@example.com"
        )
    )

    assert "/sensitive/" not in payload["message"]
    assert "top-secret" not in payload["message"]
    assert "another-secret" not in payload["message"]
    assert "third-secret" not in payload["message"]
    assert "operator@example.com" not in payload["message"]
