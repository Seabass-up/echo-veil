from __future__ import annotations

from io import BytesIO
import json
import math
from pathlib import Path
import sqlite3
from typing import Any

import numpy as np
import pytest

from echo_veil.agent_cli import MAX_REQUEST_BYTES, McpServer, TOOLS, _read_mcp_line
import echo_veil.agent_memory as agent_memory
from echo_veil.agent_memory import (
    AgentMemory,
    DEFAULT_SEMANTIC_MIN_SCORE,
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
            return Response({"embeddings": [vector]})

        def close(self) -> None:
            return None

    monkeypatch.setattr(agent_memory.http.client, "HTTPConnection", Connection)
    embedder = OllamaTextEmbedder(dimension=32, timeout_seconds=2)
    document = embedder.embed_document("The launch code is blue.")
    query = embedder.embed_query("What color is the launch code?")

    assert f"@sha256:{digest}" in embedder.identity
    assert np.linalg.norm(document) == pytest.approx(1.0)
    assert np.linalg.norm(query) == pytest.approx(1.0)
    document_body = json.loads(requests[-2][2] or b"{}")
    query_body = json.loads(requests[-1][2] or b"{}")
    assert document_body["input"] == ["The launch code is blue."]
    assert query_body["input"][0].startswith("Instruct: ")
    assert query_body["input"][0].endswith("Query: What color is the launch code?")

    with pytest.raises(ValueError, match="loopback IP literal"):
        OllamaTextEmbedder(base_url="http://localhost:11434", dimension=32)
    with pytest.raises(ValueError, match="loopback IP literal"):
        OllamaTextEmbedder(base_url="http://192.0.2.1:11434", dimension=32)


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
    assert report["capability_report"]["overall_status"] == "blocked"
    assert any("not the production enclave" in item for item in report["limitations"])


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
    assert len(listed["result"]["tools"]) == 5
    assert remembered is not None
    assert remembered["result"]["isError"] is False
    assert remembered["result"]["structuredContent"]["created"] is True
    assert refused_reindex is not None
    assert refused_reindex["result"]["isError"] is True
    assert reindexed is not None
    assert reindexed["result"]["isError"] is False
    assert reindexed["result"]["structuredContent"]["reindexed"] == 1


def test_mcp_line_reader_bounds_and_drains_oversized_requests() -> None:
    stream = BytesIO(b"x" * (MAX_REQUEST_BYTES + 50) + b"\n{}\n")

    first, oversized = _read_mcp_line(stream)
    second, second_oversized = _read_mcp_line(stream)

    assert len(first) == MAX_REQUEST_BYTES + 1
    assert oversized is True
    assert second == b"{}\n"
    assert second_oversized is False
