from __future__ import annotations

import base64
import http.client
from io import BytesIO
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import time
from typing import Any

import numpy as np
import pytest

import echo_veil.agent_memory as agent_memory_module
import echo_veil.agent_security as agent_security
import echo_veil.memory_layers as memory_layers
from scripts import migrate_agent_profile, migrate_host_memory
from echo_veil.agent_cli import (
    MAX_REQUEST_BYTES,
    McpServer,
    TOOLS,
    _RuntimeAvailabilityMemory,
    build_parser,
    _public_error,
    _read_mcp_line,
    dispatch,
    main as agent_main,
)
from echo_veil._json import strict_json_loads
from echo_veil.agent_memory import (
    AgentMemory,
    AlwaysAvailableMemory,
    DEFAULT_SEMANTIC_MIN_SCORE,
    EmbeddingUnavailable,
    HashingTextEmbedder,
    OllamaTextEmbedder,
    _is_sqlite_lock_error,
    _LegacyEncryptedPayloadStore,
    _predicate_query,
)
from echo_veil.memory_layers import MemoryLayer


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


def test_agent_cli_honors_explicit_state_directory_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ECHO_VEIL_STATE_DIR", str(tmp_path))

    args = build_parser().parse_args(["doctor"])

    assert args.state_dir == tmp_path
    assert args.operator_tools is False


def test_agent_cli_requires_explicit_operator_tool_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = build_parser()
    assert parser.parse_args(["mcp"]).operator_tools is False
    assert parser.parse_args(["--operator-tools", "mcp"]).operator_tools is True

    monkeypatch.setenv("ECHO_VEIL_OPERATOR_TOOLS", "true")
    assert build_parser().parse_args(["mcp"]).operator_tools is True


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


def test_ordinary_recall_is_lifecycle_neutral(tmp_path: Path) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        memory.remember("deployment location", "Current project documents live here.")
        ordinary = memory.recall("Where should company files be kept?")
        mutated = memory.recall(
            "Where should company files be kept?",
            mutate_lifecycle=True,
        )

    assert ordinary["lifecycle_mutated"] is False
    assert mutated["lifecycle_mutated"] is True
    recall_tool = next(tool for tool in TOOLS if tool["name"] == "echo_veil_recall")
    assert "lifecycle-neutral" in recall_tool["description"]
    assert recall_tool["annotations"]["readOnlyHint"] is True


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


def test_semantic_recall_preserves_protected_competing_pair_without_invention(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        first = memory.remember(
            "service routing",
            "The service uses route alpha.",
            provenance=["operator:first-observation"],
        )
        second = memory.remember(
            "service routing",
            "The service uses route beta.",
            provenance=["operator:second-observation"],
        )

        recalled = memory.recall("Which service route applies?", top_k=1)

    assert {item["vine_id"] for item in recalled["results"]} == {
        first["vine_id"],
        second["vine_id"],
    }
    assert recalled["requested_top_k"] == 1
    assert recalled["effective_top_k"] == 2
    assert recalled["competing_pair_auto_expanded"] is True
    assert recalled["competing_pair_preserved"] is True
    assert recalled["competing_memory_detected"] is True
    assert recalled["ranking_ambiguous"] is False
    assert recalled["competing_memory_groups_omitted"] == 0
    group = recalled["competing_memory_groups"][0]
    assert group["status"] == "possible_conflict"
    assert group["protected_topic_basis"] is True
    assert group["topic_exposed"] is False
    assert group["resolution_status"] == "not_evaluated"
    assert "compatibility was not inferred" in group["basis"]
    assert "Explicitly supersede" in group["resolution_guidance"]
    assert set(group["member_ids"]) == {
        first["vine_id"],
        second["vine_id"],
    }
    assert all(item["possible_conflict"] is True for item in recalled["results"])
    assert all(
        item["competing_memory_group"] == group["group_id"]
        for item in recalled["results"]
    )
    assert {tuple(item["provenance"]) for item in recalled["results"]} == {
        ("operator:first-observation",),
        ("operator:second-observation",),
    }
    assert recalled["memory_contract"]["protected_conflict_basis"] is True
    assert recalled["memory_contract"]["conflict_compatibility_inferred"] is False


def test_all_four_semantic_layers_use_record_bound_shielded_contracts(
    tmp_path: Path,
) -> None:
    provenance_secret = "private-provenance-reference-echo-441"
    promotion_secret = "reviewed-because-echo-442"
    with AgentMemory(tmp_path) as memory:
        short = memory.remember(
            "current task",
            "The current task remains open.",
            provenance=["agent:current-task"],
        )
        long_candidate = memory.remember(
            "stable preference",
            "The user prefers concise operational reports.",
            provenance=[provenance_secret],
        )
        long = memory.promote(
            str(long_candidate["vine_id"]),
            "long_term",
            reason=promotion_secret,
        )
        live = memory.remember(
            "active tool result",
            "The current verification command passed.",
            layer="live",
            provenance=["tool:verification"],
            expires_at=time.time() + 300.0,
        )
        logic = memory.remember(
            "decision rationale",
            "Use the verified command because it exercises the installed runtime.",
            layer="contextual_logic",
            provenance=["decision:runtime-verification"],
            promotion_reason="The cited records establish the decision.",
            logic_kind="decision",
            related_ids=[str(short["vine_id"]), str(long["vine_id"])],
        )

        recalled = memory.recall(
            "Why use the verified installed runtime command?",
            top_k=5,
            allow_inferential=True,
        )
        report = memory.doctor()

    result = next(
        item for item in recalled["results"] if item["vine_id"] == logic["vine_id"]
    )
    assert result["memory_layer"] == "contextual_logic"
    assert result["provenance"] == ["decision:runtime-verification"]
    assert result["contextual_logic"] == {
        "kind": "decision",
        "related_ids": [short["vine_id"], long["vine_id"]],
    }
    assert result["layer_contract_protected"] is True
    assert live["memory_layer"] == "live"
    assert report["memory_layers"]["counts"] == {
        "live": 1,
        "short_term": 1,
        "long_term": 1,
        "contextual_logic": 1,
    }
    assert report["memory_layers"]["all_records_shielded"] is True

    database = sqlite3.connect(tmp_path / "default" / "payloads.db")
    protected_values = {
        str(row[0]): str(row[1])
        for row in database.execute(
            """
            SELECT key, value FROM adapter_metadata
            WHERE key LIKE 'memory_contract:%'
            """
        )
    }
    database.close()
    logic_envelope = protected_values[f"memory_contract:{logic['vine_id']}"]
    for sensitive_value in (
        "contextual_logic",
        "decision:runtime-verification",
        "The cited records establish the decision.",
        str(short["vine_id"]),
        str(long["vine_id"]),
    ):
        assert sensitive_value not in logic_envelope
    assert set(json.loads(logic_envelope)) == {
        "algorithm",
        "ciphertext_b64",
        "key_id",
        "nonce_b64",
        "object_type",
        "record_id",
        "schema_version",
        "scope_id",
    }

    for path in (tmp_path / "default").iterdir():
        if not path.is_file():
            continue
        contents = path.read_bytes()
        assert provenance_secret.encode() not in contents
        assert promotion_secret.encode() not in contents


def test_recall_can_scope_layers_without_rewriting_scores(tmp_path: Path) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        short = memory.remember("short policy", "The short policy applies.")
        candidate = memory.remember("stable policy", "The stable policy applies.")
        long_term = memory.promote(
            str(candidate["vine_id"]),
            "long_term",
            reason="The policy was explicitly confirmed.",
            provenance=["review:explicit-confirmation"],
        )

        unfiltered = memory.recall("Which policy applies?", top_k=5)
        filtered = memory.recall(
            "Which policy applies?",
            top_k=5,
            layers=["long_term"],
        )

        with pytest.raises(ValueError, match="duplicate"):
            memory.recall(
                "Which policy applies?",
                layers=["long_term", "long_term"],
            )
        with pytest.raises(ValueError, match="unsupported memory layer"):
            memory.recall("Which policy applies?", layers=["archive"])

    unfiltered_score = next(
        item["score"]
        for item in unfiltered["results"]
        if item["vine_id"] == long_term["vine_id"]
    )
    assert short["vine_id"] != long_term["vine_id"]
    assert filtered["requested_layers"] == ["long_term"]
    assert filtered["layers_involved"] == ["long_term"]
    assert [item["vine_id"] for item in filtered["results"]] == [long_term["vine_id"]]
    assert filtered["results"][0]["score"] == unfiltered_score


def test_bounded_inventory_filters_layers_and_topic_without_lifecycle_mutation(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        older = memory.remember(
            "AIP / supervisor / older",
            "Older AIP supervisor state.",
            effective_at=100.0,
            provenance=["aip:supervisor"],
        )
        newer = memory.remember(
            "AIP / supervisor / newer",
            "Newer AIP supervisor state.",
            effective_at=200.0,
            provenance=["aip:supervisor"],
        )
        memory.remember(
            "AIP / project / unrelated",
            "A different AIP domain.",
            effective_at=300.0,
            provenance=["aip:project"],
        )
        vine = memory.oracle.workspace.get(str(newer["vine_id"]))
        assert vine is not None
        touched_before = vine.last_touched
        score_before = vine.score

        listed = memory.list_memories(
            limit=2,
            layers=["short_term"],
            topic_prefix="AIP / supervisor /",
            newest_first=True,
        )

        vine_after = memory.oracle.workspace.get(str(newer["vine_id"]))
        assert vine_after is not None
        assert [item["vine_id"] for item in listed] == [
            newer["vine_id"],
            older["vine_id"],
        ]
        assert all(item["memory_layer"] == "short_term" for item in listed)
        assert vine_after.last_touched == touched_before
        assert vine_after.score == score_before


def test_rpc_inventory_is_capped_nonsemantic_and_reports_layers(tmp_path: Path) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        memory.remember(
            "AIP / supervisor / first",
            "First bounded inventory record.",
            effective_at=100.0,
            provenance=["aip:supervisor"],
        )
        memory.remember(
            "AIP / supervisor / second",
            "Second bounded inventory record.",
            effective_at=200.0,
            provenance=["aip:supervisor"],
        )

        response = dispatch(
            memory,
            "list",
            {
                "limit": 1,
                "layers": ["short_term"],
                "topic_prefix": "AIP / supervisor /",
                "newest_first": True,
            },
            caller="aip",
        )
        with pytest.raises(ValueError, match="between 1 and 100"):
            dispatch(memory, "list", {"limit": 101}, caller="aip")

    assert response["count"] == 1
    assert response["truncated"] is True
    assert response["inventory_only"] is True
    assert response["semantic_retrieval_performed"] is False
    assert response["lifecycle_mutated"] is False
    assert response["layers_involved"] == ["short_term"]
    assert response["results"][0]["topic"] == "AIP / supervisor / second"


def test_context_returns_bounded_authenticated_trace_without_synthesis(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        first = memory.remember(
            "runtime evidence",
            "The installed runtime completed the verification.",
            provenance=["tool:installed-runtime"],
        )
        second = memory.remember(
            "source evidence",
            "The source suite completed the verification.",
            provenance=["tool:source-suite"],
        )
        nested = memory.remember(
            "verification conclusion",
            "Both verification paths support the conclusion.",
            layer="contextual_logic",
            provenance=["decision:verification"],
            promotion_reason="Two authenticated records support the conclusion.",
            logic_kind="causal_chain",
            related_ids=[str(first["vine_id"]), str(second["vine_id"])],
        )
        root = memory.remember(
            "release decision",
            "The verified conclusion supports the release decision.",
            layer="contextual_logic",
            provenance=["decision:release"],
            promotion_reason="The protected verification conclusion is required.",
            logic_kind="decision",
            related_ids=[str(nested["vine_id"])],
        )

        traced = memory.context(
            "Which protected reasoning applies?",
            max_depth=2,
            max_records=3,
        )
        bounded = memory.context(
            "Which protected reasoning applies?",
            max_depth=2,
            max_records=1,
        )

    assert traced["logic_roots"][0]["vine_id"] in {
        root["vine_id"],
        nested["vine_id"],
    }
    assert traced["context_contract"] == {
        "query_driven_roots": True,
        "root_confidence_gates_preserved": True,
        "outgoing_links_only": True,
        "evidence_query_scored": False,
        "synthesis_performed": False,
        "layer_relationships_protected": True,
    }
    assert traced["ranking_ambiguous"] is True
    assert 1 <= len(traced["evidence"]) <= 3
    assert all(item["query_scored"] is False for item in traced["evidence"])
    assert all(
        item["confidence_basis"] == "protected_contextual_link"
        for item in traced["evidence"]
    )
    assert all(item["layer_contract_protected"] is True for item in traced["evidence"])
    assert all(
        "not independently query-scored" in item["confidence_indicator"]
        for item in traced["evidence"]
    )
    assert len(bounded["evidence"]) == 1
    assert bounded["truncated"] is True
    assert bounded["queued_links_omitted"] > 0
    assert bounded["incomplete"] is True


def test_context_does_not_expand_confidence_gated_logic_root(tmp_path: Path) -> None:
    class InferentialEmbedder(_SemanticTestEmbedder):
        identity = "test:inferential:v1:dimension:32"
        default_min_score = 0.35

        def embed_query(self, _text: str) -> np.ndarray[Any, np.dtype[np.float64]]:
            vector = np.zeros(self.dimension)
            vector[0] = 0.40
            vector[1] = math.sqrt(1.0 - 0.40**2)
            return vector

    with AgentMemory(tmp_path, embed=InferentialEmbedder()) as memory:
        evidence = memory.remember("evidence", "The evidence remains protected.")
        logic = memory.remember(
            "tentative decision",
            "The tentative decision references the evidence.",
            layer="contextual_logic",
            provenance=["decision:tentative"],
            promotion_reason="The evidence is relevant but confidence remains low.",
            logic_kind="decision",
            related_ids=[str(evidence["vine_id"])],
        )

        traced = memory.context("Why was the tentative decision made?")

    assert traced["logic_roots"][0]["vine_id"] == logic["vine_id"]
    assert traced["logic_roots"][0]["gated"] is True
    assert traced["logic_roots"][0]["payload"] is None
    assert traced["root_expansion"] == [
        {
            "vine_id": logic["vine_id"],
            "expanded": False,
            "status": "confidence_gated",
        }
    ]
    assert traced["evidence"] == []
    assert traced["incomplete"] is True


def test_context_omits_tampered_linked_evidence(tmp_path: Path) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        evidence = memory.remember(
            "authenticated evidence",
            "The authenticated evidence supports the decision.",
        )
        logic = memory.remember(
            "protected decision",
            "The protected decision cites authenticated evidence.",
            layer="contextual_logic",
            provenance=["decision:protected"],
            promotion_reason="The authenticated source supports the decision.",
            logic_kind="decision",
            related_ids=[str(evidence["vine_id"])],
        )

        database = sqlite3.connect(tmp_path / "default" / "payloads.db")
        key = f"memory_contract:{evidence['vine_id']}"
        encoded = str(
            database.execute(
                "SELECT value FROM adapter_metadata WHERE key = ?",
                (key,),
            ).fetchone()[0]
        )
        envelope = json.loads(encoded)
        ciphertext = bytearray(
            base64.urlsafe_b64decode(str(envelope["ciphertext_b64"]).encode())
        )
        ciphertext[-1] ^= 1
        envelope["ciphertext_b64"] = base64.urlsafe_b64encode(ciphertext).decode()
        database.execute(
            "UPDATE adapter_metadata SET value = ? WHERE key = ?",
            (json.dumps(envelope, sort_keys=True, separators=(",", ":")), key),
        )
        database.commit()
        database.close()

        traced = memory.context("Why is the protected decision supported?")

    assert traced["logic_roots"][0]["vine_id"] == logic["vine_id"]
    assert traced["evidence"] == []
    assert traced["context_edges"] == [
        {
            "from": logic["vine_id"],
            "to": evidence["vine_id"],
            "depth": 1,
            "logic_kind": "decision",
            "status": "authentication_failed",
        }
    ]
    assert traced["incomplete"] is True


def test_context_omits_evidence_not_valid_at_requested_time(tmp_path: Path) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        evidence = memory.remember(
            "later evidence",
            "This evidence became valid later.",
            effective_at=200.0,
        )
        logic = memory.remember(
            "earlier decision",
            "The decision record predates its later supporting evidence.",
            effective_at=100.0,
            layer="contextual_logic",
            provenance=["decision:historical"],
            promotion_reason="Synthetic temporal-boundary test.",
            logic_kind="decision",
            related_ids=[str(evidence["vine_id"])],
        )

        traced = memory.context(
            "Why was the earlier decision recorded?",
            as_of=150.0,
        )

    assert traced["logic_roots"][0]["vine_id"] == logic["vine_id"]
    assert traced["evidence"] == []
    assert traced["context_edges"][0]["status"] == "not_valid_at_as_of"
    assert traced["incomplete"] is True


def test_pre_contract_scoped_profile_migrates_to_protected_short_term(
    tmp_path: Path,
) -> None:
    scope = "workspace:pre-contract-migration"
    with AgentMemory(tmp_path, scope=scope) as memory:
        created = memory.remember(
            "existing protected record",
            "This record predates the semantic-layer contract.",
        )

    profile = tmp_path / "default"
    database = sqlite3.connect(profile / "payloads.db")
    database.execute("DELETE FROM adapter_metadata WHERE key LIKE 'memory_contract%'")
    database.execute("DELETE FROM adapter_metadata WHERE key LIKE 'record_integrity%'")
    database.commit()
    database.close()
    manifest_path = profile / "keyring.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["features"]
    key = (
        profile / str(manifest["keys"][manifest["active_key_id"]]["ref"])
    ).read_bytes()
    manifest["scope_binding"] = agent_security._scope_binding(
        key,
        scope,
        str(manifest["scope_id"]),
    )
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)

    with AgentMemory(tmp_path, scope=scope) as migrated:
        report = migrated.doctor()
        record = next(
            item
            for item in migrated.list_memories()
            if item["vine_id"] == created["vine_id"]
        )

    assert report["migrated_memory_contracts"] == 1
    assert report["memory_layers"]["all_records_shielded"] is True
    assert record["memory_layer"] == "short_term"
    assert record["provenance"] == ["migration:pre-layer-contract"]
    migrated_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert migrated_manifest["features"] == [
        "record-integrity-hmac-v1",
        "shielded-four-layer-v1",
    ]


def test_direct_long_term_write_is_blocked_until_explicit_promotion(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path) as memory:
        with pytest.raises(ValueError, match="must be promoted"):
            memory.remember(
                "unreviewed durable claim",
                "This claim has not passed short-term review.",
                layer="long_term",
                provenance=["agent:proposal"],
                promotion_reason="The caller attempted to skip review.",
            )


def test_seed_crystal_policy_bounds_layers_and_rejects_raw_transcripts(
    tmp_path: Path,
) -> None:
    transcript = (
        "User: Please check the deployment.\n"
        "Assistant: I am checking it now.\n"
        "Tool: The deployment is healthy.\n"
        "Assistant: The deployment passed."
    )
    with AgentMemory(tmp_path) as memory:
        live = memory.remember(
            "active deployment exchange",
            transcript,
            layer="live",
            provenance=["session:active-turn"],
            expires_at=time.time() + 600.0,
        )
        assert live["content_policy"]["raw_transcript_detected"] is True
        assert live["content_policy"]["policy_compliant"] is True
        assert live["content_policy"]["automatic_rewriting_performed"] is False
        assert live["promotion_recommendation"] == (
            "compact_before_short_term_promotion_or_discard"
        )

        with pytest.raises(ValueError, match="raw transcript"):
            memory.remember("session dump", transcript)
        with pytest.raises(ValueError, match="raw transcript"):
            memory.remember(
                "short exchange",
                "User: Is the deployment ready?\nAssistant: The deployment passed.",
            )
        with pytest.raises(ValueError, match="raw transcript"):
            memory.remember(
                "serialized exchange",
                (
                    '[{"role":"user","content":"Is it ready?"},'
                    '{"role":"assistant","content":"It passed."}]'
                ),
            )
        with pytest.raises(ValueError, match="raw transcript"):
            memory.promote(
                str(live["vine_id"]),
                "short_term",
                reason="Raw dialogue must not escape Live memory.",
            )
        with pytest.raises(ValueError, match="12000-character"):
            memory.remember("oversized short state", "s" * 12_001)

        long_candidate = memory.remember(
            "durable candidate",
            "d" * 2_001,
            provenance=["source:reviewed-record"],
        )
        with pytest.raises(ValueError, match="2000-character"):
            memory.promote(
                str(long_candidate["vine_id"]),
                "long_term",
                reason="The record was reviewed but remains too verbose.",
                provenance=["review:explicit"],
            )


def test_live_refresh_preserves_changed_history_and_renews_unchanged_state(
    tmp_path: Path,
) -> None:
    now = time.time()
    with AgentMemory(tmp_path) as memory:
        original = memory.remember(
            "active deployment state",
            "The deployment is preparing.",
            layer="live",
            provenance=["agent:deployment-loop"],
            expires_at=now + 600.0,
        )
        same = memory.refresh_live(
            str(original["vine_id"]),
            "The deployment is preparing.",
            provenance=["tool:status-poll"],
            expires_at=now + 1_200.0,
        )
        assert same["vine_id"] == original["vine_id"]
        assert same["previous_vine_id"] == original["vine_id"]
        assert same["created"] is False
        assert same["duplicate"] is False
        assert same["refreshed"] is True
        assert same["content_changed"] is False
        assert same["expires_at"] == pytest.approx(now + 1_200.0)
        assert same["provenance"] == [
            "agent:deployment-loop",
            "tool:status-poll",
        ]

        changed = memory.refresh_live(
            str(original["vine_id"]),
            "The deployment completed successfully.",
            provenance=["receipt:deployment-pass"],
            expires_at=now + 1_800.0,
        )
        assert changed["vine_id"] != original["vine_id"]
        assert changed["previous_vine_id"] == original["vine_id"]
        assert changed["refreshed"] is True
        assert changed["content_changed"] is True
        assert changed["supersedes"] == [original["vine_id"]]
        assert changed["memory_layer"] == "live"
        assert changed["provenance"] == [
            "agent:deployment-loop",
            "tool:status-poll",
            "receipt:deployment-pass",
        ]

        records = {str(item["vine_id"]): item for item in memory.list_memories()}
        assert (
            records[str(original["vine_id"])]["superseded_by"] == (changed["vine_id"])
        )
        assert records[str(changed["vine_id"])]["superseded_by"] is None
        assert records[str(changed["vine_id"])]["payload"] == (
            "The deployment completed successfully."
        )
        with pytest.raises(ValueError, match="superseded"):
            memory.refresh_live(
                str(original["vine_id"]),
                "A stale process must not rewrite the old Live version.",
            )

    with AgentMemory(tmp_path) as restored:
        records = {str(item["vine_id"]): item for item in restored.list_memories()}
        assert (
            records[str(original["vine_id"])]["superseded_by"] == (changed["vine_id"])
        )
        assert records[str(changed["vine_id"])]["superseded_by"] is None

    protected_store = (tmp_path / "default" / "payloads.db").read_bytes()
    for protected_value in (
        b"The deployment is preparing.",
        b"The deployment completed successfully.",
        b"agent:deployment-loop",
        b"tool:status-poll",
        b"receipt:deployment-pass",
    ):
        assert protected_value not in protected_store


def test_layer_promotion_is_explicit_and_survives_restart(tmp_path: Path) -> None:
    with AgentMemory(tmp_path) as memory:
        live = memory.remember(
            "active deployment check",
            "The deployment check is still running.",
            layer=MemoryLayer.LIVE,
            provenance=["agent:deployment-loop"],
            expires_at=time.time() + 600.0,
        )
        short = memory.promote(
            str(live["vine_id"]),
            "short_term",
            reason="The check remains open across the next session.",
            provenance=["task:open-loop"],
        )
        long = memory.promote(
            str(live["vine_id"]),
            "long_term",
            reason="The procedure was independently verified.",
            provenance=["evidence:verification-receipt"],
        )

        assert short["previous_layer"] == "live"
        assert short["memory_layer"] == "short_term"
        assert long["previous_layer"] == "short_term"
        assert long["memory_layer"] == "long_term"
        with pytest.raises(ValueError, match="unsupported memory promotion"):
            memory.promote(
                str(live["vine_id"]),
                "short_term",
                reason="Long-term memory cannot silently move backward.",
            )

    with AgentMemory(tmp_path) as restored:
        record = next(
            item
            for item in restored.list_memories()
            if item["vine_id"] == live["vine_id"]
        )

    assert record["memory_layer"] == "long_term"
    assert record["expires_at"] is None
    assert record["provenance"] == [
        "agent:deployment-loop",
        "task:open-loop",
        "evidence:verification-receipt",
    ]
    assert record["promotion_evidence"]["from"] == "short_term"
    assert [event["from"] for event in record["promotion_history"]] == [
        "live",
        "short_term",
    ]


def test_expired_live_memory_is_pruned_without_archival(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 1_000.0}
    monkeypatch.setattr(memory_layers.time, "time", lambda: clock["now"])
    with AgentMemory(tmp_path) as memory:
        created = memory.remember(
            "ephemeral tool output",
            "This output must disappear after the live window.",
            layer="live",
            provenance=["tool:ephemeral"],
            expires_at=1_100.0,
        )
        clock["now"] = 1_200.0

        assert memory.list_memories() == []
        assert memory.oracle.archived_metadata(str(created["vine_id"])) is None
        assert memory.doctor()["authenticated_deletion_records"] == 1


def test_contextual_logic_rejects_unknown_relationships(tmp_path: Path) -> None:
    with AgentMemory(tmp_path) as memory:
        with pytest.raises(ValueError, match="unknown memory"):
            memory.remember(
                "unsupported conclusion",
                "This conclusion has no stored evidence.",
                layer="contextual_logic",
                provenance=["agent:derived"],
                promotion_reason="Synthetic negative test.",
                logic_kind="principle",
                related_ids=["f" * 32],
            )


def test_agent_adapter_detects_and_rejects_unpaired_low_level_vines(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path) as memory:
        bypass = memory.oracle.sprout("low-level-bypass", np.ones(384))

        report = memory.doctor()
        assert report["adapter_ready"] is False
        assert report["readiness"]["healthy"] is False
        assert report["memory_layers"]["all_records_shielded"] is False
        assert report["memory_layers"]["unpaired_lifecycle_record_count"] == 1
        with pytest.raises(ValueError, match="unknown memory"):
            memory.remember(
                "invalid derived decision",
                "A semantic record cannot cite an unpaired low-level vine.",
                layer="contextual_logic",
                provenance=["decision:invalid"],
                promotion_reason="The cited source has no layer contract.",
                logic_kind="decision",
                related_ids=[bypass.vine_id],
            )


def test_forget_cascades_through_protected_contextual_logic(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path) as memory:
        source = memory.remember(
            "source fact",
            "The source fact supports a protected decision.",
            provenance=["record:source"],
        )
        logic = memory.remember(
            "derived decision",
            "Use the source fact when making the decision.",
            layer="contextual_logic",
            provenance=["decision:derived"],
            promotion_reason="The source record directly supports this decision.",
            logic_kind="decision",
            related_ids=[str(source["vine_id"])],
        )
        nested = memory.remember(
            "derived principle",
            "The protected decision establishes a reusable principle.",
            layer="contextual_logic",
            provenance=["principle:derived"],
            promotion_reason="The decision record establishes the principle.",
            logic_kind="principle",
            related_ids=[str(logic["vine_id"])],
        )

        forgotten = memory.forget(str(source["vine_id"]))

        assert forgotten["cascade_deleted_contextual_logic"] == [
            nested["vine_id"],
            logic["vine_id"],
        ]
        assert memory.list_memories() == []


def test_tampered_layer_contract_fails_closed_on_restart(tmp_path: Path) -> None:
    with AgentMemory(tmp_path) as memory:
        created = memory.remember(
            "protected policy",
            "The protected policy must retain authenticated provenance.",
            provenance=["policy:source"],
        )

    path = tmp_path / "default" / "payloads.db"
    database = sqlite3.connect(path)
    key = f"memory_contract:{created['vine_id']}"
    encoded = str(
        database.execute(
            "SELECT value FROM adapter_metadata WHERE key = ?",
            (key,),
        ).fetchone()[0]
    )
    envelope = json.loads(encoded)
    ciphertext = bytearray(
        base64.urlsafe_b64decode(str(envelope["ciphertext_b64"]).encode())
    )
    ciphertext[0] ^= 1
    envelope["ciphertext_b64"] = base64.urlsafe_b64encode(ciphertext).decode()
    database.execute(
        "UPDATE adapter_metadata SET value = ? WHERE key = ?",
        (json.dumps(envelope, sort_keys=True, separators=(",", ":")), key),
    )
    database.commit()
    database.close()

    with pytest.raises(RuntimeError, match="contract"):
        AgentMemory(tmp_path)


def test_missing_layer_contract_fails_closed_on_restart(tmp_path: Path) -> None:
    with AgentMemory(tmp_path) as memory:
        created = memory.remember(
            "protected policy",
            "The protected policy must not lose its layer contract.",
            provenance=["policy:source"],
        )

    path = tmp_path / "default" / "payloads.db"
    database = sqlite3.connect(path)
    database.execute(
        "DELETE FROM adapter_metadata WHERE key = ?",
        (f"memory_contract:{created['vine_id']}",),
    )
    database.commit()
    database.close()

    with pytest.raises(RuntimeError, match="contract"):
        AgentMemory(tmp_path)


def test_removing_all_layer_contract_state_cannot_downgrade_profile(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path) as memory:
        memory.remember(
            "protected policy",
            "The protected policy requires its migration marker.",
            provenance=["policy:source"],
        )

    path = tmp_path / "default" / "payloads.db"
    database = sqlite3.connect(path)
    database.execute("DELETE FROM adapter_metadata WHERE key LIKE 'memory_contract%'")
    database.commit()
    database.close()

    with pytest.raises(RuntimeError, match="required protected memory contract"):
        AgentMemory(tmp_path)


def test_layer_contract_cannot_be_transplanted_between_records(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path) as memory:
        first = memory.remember(
            "first protected record",
            "The first record has independent provenance.",
            provenance=["record:first"],
        )
        second = memory.remember(
            "second protected record",
            "The second record has independent provenance.",
            provenance=["record:second"],
        )

    path = tmp_path / "default" / "payloads.db"
    database = sqlite3.connect(path)
    first_key = f"memory_contract:{first['vine_id']}"
    second_key = f"memory_contract:{second['vine_id']}"
    first_value = database.execute(
        "SELECT value FROM adapter_metadata WHERE key = ?",
        (first_key,),
    ).fetchone()[0]
    second_value = database.execute(
        "SELECT value FROM adapter_metadata WHERE key = ?",
        (second_key,),
    ).fetchone()[0]
    database.execute(
        "UPDATE adapter_metadata SET value = ? WHERE key = ?",
        (second_value, first_key),
    )
    database.execute(
        "UPDATE adapter_metadata SET value = ? WHERE key = ?",
        (first_value, second_key),
    )
    database.commit()
    database.close()

    with pytest.raises(RuntimeError, match="contract"):
        AgentMemory(tmp_path)


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
    assert _predicate_query(query) == expected


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
    with AgentMemory(tmp_path):
        with pytest.raises(RuntimeError, match="another writer"):
            AgentMemory(tmp_path, profile_lock_timeout_seconds=0.01)

    with AgentMemory(tmp_path, profile_lock_timeout_seconds=0.01) as reopened:
        assert reopened.doctor()["writer_serialization"] == "profile-sqlite-lease"


def test_sqlite_lock_detection_supports_legacy_and_extended_errors() -> None:
    legacy = sqlite3.OperationalError("database is locked")
    extended = sqlite3.OperationalError("synthetic extended busy result")
    extended.sqlite_errorcode = 773  # type: ignore[attr-defined]

    assert _is_sqlite_lock_error(legacy) is True
    assert _is_sqlite_lock_error(extended) is True
    assert (
        _is_sqlite_lock_error(
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
    profile = agent_memory_module._secure_directory(tmp_path / "default")
    key_path = profile / "agent.key"
    key = agent_memory_module._load_or_create_key(key_path)
    store = _LegacyEncryptedPayloadStore(
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
        with pytest.raises(RuntimeError, match="migration-only"):
            memory.remember("blocked legacy write", "Never create partial protection.")
        with pytest.raises(RuntimeError, match="migration-only"):
            memory.recall("blocked legacy recall")

    assert report["security_schema"] == "legacy-v1"
    assert report["memory_layers"]["all_records_shielded"] is False
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

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    embedder = OllamaTextEmbedder(
        dimension=32,
        timeout_seconds=2,
        keep_alive_seconds=300,
        context_length=16_384,
        gpu_layers=0,
    )
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
    assert document_body["keep_alive"] == "300s"
    assert query_body["keep_alive"] == "300s"
    assert document_body["options"] == {"num_ctx": 16_384, "num_gpu": 0}
    assert query_body["options"] == {"num_ctx": 16_384, "num_gpu": 0}
    assert query_body["input"][0].startswith("Instruct: ")
    assert "Taylor" not in query_body["input"][1]
    assert query_body["input"][1].endswith("Query: What is passport number?")
    assert query_body["input"][0].endswith("Query: What is Taylor's passport number?")

    with pytest.raises(ValueError, match="loopback IP literal"):
        OllamaTextEmbedder(base_url="http://localhost:11434", dimension=32)
    with pytest.raises(ValueError, match="loopback IP literal"):
        OllamaTextEmbedder(base_url="http://192.0.2.1:11434", dimension=32)
    with pytest.raises(TypeError, match="keep-alive"):
        OllamaTextEmbedder(dimension=32, keep_alive_seconds=True)
    with pytest.raises(ValueError, match="between 0 and 3600"):
        OllamaTextEmbedder(dimension=32, keep_alive_seconds=-1)
    with pytest.raises(ValueError, match="between 0 and 3600"):
        OllamaTextEmbedder(dimension=32, keep_alive_seconds=3_601)
    with pytest.raises(TypeError, match="context length"):
        OllamaTextEmbedder(dimension=32, context_length=True)
    with pytest.raises(ValueError, match="between 512 and 262144"):
        OllamaTextEmbedder(dimension=32, context_length=511)
    with pytest.raises(TypeError, match="GPU layers"):
        OllamaTextEmbedder(dimension=32, gpu_layers=False)
    with pytest.raises(ValueError, match="between 0 and 2048"):
        OllamaTextEmbedder(dimension=32, gpu_layers=2_049)


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

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
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

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
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
        memory.remember(
            "deployment outage decision",
            "Use the opal harbor procedure because the recovery record is verified.",
            layer="contextual_logic",
            provenance=["decision:outage-recovery"],
            promotion_reason="The recovery record supports this decision.",
            logic_kind="decision",
            related_ids=[str(created["vine_id"])],
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
        context = available.context(
            "deployment outage decision opal harbor procedure",
        )
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
        assert context["degraded"] is True
        assert context["semantic_available"] is False
        assert context["lifecycle_mutated"] is False
        assert context["logic_roots"][0]["memory_layer"] == "contextual_logic"
        assert context["evidence"][0]["vine_id"] == created["vine_id"]
        assert context["evidence"][0]["query_scored"] is False
        assert doctor["mode"] == "always-available-read-only"
        assert doctor["writes_available"] is False
        assert doctor["retrieval"]["candidate_limit"] == 900
        assert doctor["retrieval"]["competing_memory"] == (
            "possible-conflict-no-inference-v1"
        )
        assert doctor["memory_layers"]["content_policy"] == ("bounded-seed-crystal-v1")
        assert doctor["memory_layers"]["live_refresh"] == "unavailable-read-only"
        with pytest.raises(ValueError, match="safe default"):
            available.recall("deployment recovery", min_score=0.44)
        with pytest.raises(RuntimeError, match="read-only"):
            available.remember("new", "not allowed")
        with pytest.raises(RuntimeError, match="read-only"):
            available.refresh_live(str(created["vine_id"]), "not allowed")
        with pytest.raises(RuntimeError, match="read-only"):
            available.forget(str(created["vine_id"]))
        with pytest.raises(RuntimeError, match="read-only"):
            available.reindex()

    assert payload_database.read_bytes() == before
    assert lifecycle_database.read_bytes() == lifecycle_before


def test_always_available_recall_preserves_protected_competing_pair(
    tmp_path: Path,
) -> None:
    query = "service routing boundary route alpha beta"
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        first = memory.remember(
            "service routing boundary",
            "The service routing boundary uses route alpha.",
        )
        second = memory.remember(
            "service routing boundary",
            "The service routing boundary uses route beta.",
        )

    with AlwaysAvailableMemory(
        tmp_path,
        reason="synthetic_embedding_outage",
    ) as available:
        recalled = available.recall(query, top_k=1)

    assert recalled["degraded"] is True
    assert recalled["semantic_available"] is False
    assert recalled["requested_top_k"] == 1
    assert recalled["effective_top_k"] == 2
    assert recalled["competing_pair_auto_expanded"] is True
    assert recalled["competing_memory_detected"] is True
    assert {item["vine_id"] for item in recalled["results"]} == {
        first["vine_id"],
        second["vine_id"],
    }
    assert all(item["possible_conflict"] is True for item in recalled["results"])
    assert recalled["competing_memory_groups"][0]["protected_topic_basis"] is True
    assert recalled["competing_memory_groups"][0]["resolution_status"] == (
        "not_evaluated"
    )


def test_rpc_availability_recall_is_manual_read_only_and_never_authorizes_turn(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        created = memory.remember(
            "opal harbor recovery procedure",
            "Use the opal harbor recovery procedure during a deployment outage.",
        )
    payload_database = tmp_path / "default" / "payloads.db"
    lifecycle_database = tmp_path / "default" / "echo-veil.db"
    payload_before = payload_database.read_bytes()
    lifecycle_before = lifecycle_database.read_bytes()

    with AlwaysAvailableMemory(tmp_path, reason="manual_read_only") as available:
        response = dispatch(
            available,
            "availability_recall",
            {"query": "opal harbor recovery procedure", "top_k": 1},
            caller="pi",
        )
        with pytest.raises(ValueError, match="unexpected arguments"):
            dispatch(
                available,
                "availability_recall",
                {
                    "query": "opal harbor recovery procedure",
                    "allow_inferential": True,
                },
                caller="pi",
            )

    assert response["results"][0]["vine_id"] == created["vine_id"]
    assert response["degraded"] is True
    assert response["semantic_available"] is False
    assert response["lifecycle_mutated"] is False
    assert response["model_turn_authorized"] is False
    assert response["mutations_allowed"] is False
    assert response["requested_top_k"] == 1
    assert response["effective_top_k"] == 2
    assert payload_database.read_bytes() == payload_before
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
    with _RuntimeAvailabilityMemory(  # noqa: SLF001 - failover contract
        primary, tmp_path, "default"
    ) as memory:
        memory.remember(
            "opal harbor recovery procedure",
            "Use the opal harbor recovery procedure during a deployment outage.",
        )
        live = memory.remember(
            "active outage state",
            "The embedding service is healthy.",
            layer="live",
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
        with pytest.raises(RuntimeError, match="read-only"):
            memory.refresh_live(
                str(live["vine_id"]),
                "The embedding service is unavailable.",
            )


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

    def run_rpc(memory: object, *, caller: str | None = None) -> int:
        observed["memory"] = memory
        observed["caller"] = caller
        return 0

    monkeypatch.setattr("echo_veil.agent_cli._build_embedder", unavailable)
    monkeypatch.setattr("echo_veil.agent_cli.run_rpc", run_rpc)

    result = agent_main(
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
    assert observed["caller"] is None

    disabled = agent_main(
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
        assert duplicate["vine_id"] == created["vine_id"]
        assert duplicate["topic"] == topic
        assert duplicate["created"] is False
        assert duplicate["duplicate"] is True
        assert duplicate["memory_layer"] == "short_term"
        assert duplicate["layer_contract_protected"] is True
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


def test_agent_memory_deduplicates_unicode_topic_and_payload(
    tmp_path: Path,
) -> None:
    topic = "host import · résumé"
    payload = "Use the reviewed café policy. ✓"

    with AgentMemory(tmp_path) as memory:
        created = memory.remember(topic, payload)
        duplicate = memory.remember(topic, payload)

    assert duplicate["vine_id"] == created["vine_id"]
    assert duplicate["created"] is False
    assert duplicate["duplicate"] is True


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
        assert historical["competing_memory_detected"] is False
        assert historical["competing_memory_groups"] == []

        memory.forget(str(current["vine_id"]))
        restored = memory.recall("Where does the service deploy?", top_k=1)
        assert restored["results"][0]["vine_id"] == old["vine_id"]
        assert restored["results"][0]["temporal_status"] == "current"
        assert restored["competing_memory_detected"] is False


def test_topic_token_swap_is_quarantined_before_conflict_signaling(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        first = memory.remember("first protected topic", "The first fact applies.")
        second = memory.remember("second protected topic", "The second fact applies.")
        database = sqlite3.connect(tmp_path / "default" / "payloads.db")
        try:
            first_token = database.execute(
                "SELECT topic FROM payloads WHERE vine_id = ?",
                (first["vine_id"],),
            ).fetchone()[0]
            database.execute(
                "UPDATE payloads SET topic = ? WHERE vine_id = ?",
                (first_token, second["vine_id"]),
            )
            database.commit()
        finally:
            database.close()

        recalled = memory.recall("Which protected fact applies?", top_k=2)
        report = memory.doctor()

    assert [item["vine_id"] for item in recalled["results"]] == [first["vine_id"]]
    assert recalled["competing_memory_detected"] is False
    assert report["quarantined_records"] == 1


def test_reindex_refuses_missing_authenticated_retrieval_data(tmp_path: Path) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        memory.remember("runbook", "Use the blue recovery runbook.")
        database = sqlite3.connect(tmp_path / "default" / "payloads.db")
        try:
            database.execute("DELETE FROM memory_vectors")
            database.commit()
        finally:
            database.close()

        doctor = memory.doctor()
        report = memory.reindex()
        assert doctor["adapter_ready"] is False
        assert doctor["quarantined_records"] == 1
        assert report["reindexed"] == 0


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


def test_profile_migration_script_uses_fresh_scoped_target_without_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with AgentMemory(tmp_path, profile="source") as source:
        original = source.remember(
            "service region",
            "The protected service region was west.",
            effective_at=100.0,
            provenance=["test:source-record"],
        )
        source.remember(
            "service region",
            "The protected service region is now central.",
            effective_at=200.0,
            supersedes=[str(original["vine_id"])],
            provenance=["test:source-correction"],
        )

    monkeypatch.setattr(
        migrate_agent_profile,
        "OllamaTextEmbedder",
        lambda **_kwargs: _SemanticTestEmbedder(),
    )
    args = migrate_agent_profile.build_parser().parse_args(
        [
            "--state-dir",
            str(tmp_path),
            "--source-profile",
            "source",
            "--target-profile",
            "target",
            "--source-embedder",
            "hashing",
            "--target-dimension",
            "32",
            "--confirm",
        ]
    )

    report = migrate_agent_profile.run(args)

    assert report["migrated"] == 2
    assert report["history_links"] == 1
    assert report["plaintext_export_created"] is False
    assert report["target_security_schema"] == "scoped-v2"
    assert report["target_all_records_shielded"] is True
    assert not list(tmp_path.rglob("*.jsonl"))
    assert not list(tmp_path.rglob("*.txt"))
    with AgentMemory(
        tmp_path,
        profile="target",
        embed=_SemanticTestEmbedder(),
    ) as target:
        recalled = target.recall("Where is the service region?", top_k=2)
    assert [item["temporal_status"] for item in recalled["results"]] == [
        "current",
        "superseded",
    ]


def test_profile_migration_script_requires_confirmation_and_new_profile() -> None:
    parser = migrate_agent_profile.build_parser()
    missing_confirmation = parser.parse_args(
        ["--source-profile", "source", "--target-profile", "target"]
    )
    same_profile = parser.parse_args(
        [
            "--source-profile",
            "source",
            "--target-profile",
            "source",
            "--confirm",
        ]
    )

    with pytest.raises(ValueError, match="requires --confirm"):
        migrate_agent_profile.run(missing_confirmation)
    with pytest.raises(ValueError, match="must be different"):
        migrate_agent_profile.run(same_profile)


def _write_owner_only_host_catalog(path: Path, records: list[str]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(records), encoding="utf-8")
    path.chmod(0o600)


def test_host_memory_migration_dry_run_reports_risk_without_payloads(
    tmp_path: Path,
) -> None:
    source = tmp_path / "host" / "memory.json"
    local_path = "/" + "Users/example/project/config.json"
    _write_owner_only_host_catalog(
        source,
        [
            "Use concise status receipts for completed work.",
            f"The old configuration lived at {local_path}.",
            "Use concise status receipts for completed work.",
        ],
    )
    args = migrate_host_memory.build_parser().parse_args(
        [
            "--source",
            str(source),
            "--state-dir",
            str(tmp_path / "state"),
            "--profile",
            "host-import",
            "--caller",
            "algo-cli",
        ]
    )

    report = migrate_host_memory.run(args)
    serialized = json.dumps(report, sort_keys=True)

    assert report["mode"] == "dry_run"
    assert report["source_records"] == 3
    assert report["unique_records"] == 2
    assert report["duplicate_source_records"] == 1
    assert report["review_required_indices"] == [1]
    assert report["review_reason_counts"] == {"developer_machine_path": 1}
    assert report["protected_write_attempted"] is False
    assert report["plaintext_source_retired"] is False
    assert report["payloads_in_report"] is False
    assert source.exists()
    assert not (tmp_path / "state").exists()
    assert "concise status" not in serialized
    assert local_path not in serialized
    assert str(source) not in serialized


def test_host_memory_migration_rejects_non_owner_only_source(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX owner-only mode policy")
    source = tmp_path / "host" / "memory.json"
    _write_owner_only_host_catalog(source, ["Reviewed seed crystal."])
    source.chmod(0o640)
    args = migrate_host_memory.build_parser().parse_args(
        [
            "--source",
            str(source),
            "--caller",
            "algo-cli",
        ]
    )

    with pytest.raises(
        migrate_host_memory.HostMemoryMigrationError,
        match="permissions must be owner-only",
    ):
        migrate_host_memory.run(args)

    assert source.exists()


def test_host_memory_migration_blocks_transcript_shaped_records(
    tmp_path: Path,
) -> None:
    source = tmp_path / "host" / "memory.json"
    transcript = "User: preserve this raw turn. Assistant: copied verbatim."
    _write_owner_only_host_catalog(source, [transcript])
    parser = migrate_host_memory.build_parser()
    base = [
        "--source",
        str(source),
        "--state-dir",
        str(tmp_path / "state"),
        "--profile",
        "host-import",
        "--caller",
        "algo-cli",
    ]

    report = migrate_host_memory.run(parser.parse_args(base))

    assert report["ineligible_indices"] == [0]
    assert report["ineligible_reason_counts"] == {"raw_transcript": 1}
    assert transcript not in json.dumps(report, sort_keys=True)
    with pytest.raises(
        migrate_host_memory.HostMemoryMigrationError,
        match="ineligible records",
    ):
        migrate_host_memory.run(
            parser.parse_args(
                [
                    *base,
                    "--confirm",
                    migrate_host_memory.IMPORT_CONFIRMATION,
                ]
            )
        )
    assert source.exists()
    assert not (tmp_path / "state").exists()


def test_host_memory_migration_requires_review_and_exact_confirmations(
    tmp_path: Path,
) -> None:
    source = tmp_path / "host" / "memory.json"
    local_path = "/" + "Users/example/project/config.json"
    _write_owner_only_host_catalog(
        source,
        [f"The old configuration lived at {local_path}."],
    )
    parser = migrate_host_memory.build_parser()
    base = [
        "--source",
        str(source),
        "--state-dir",
        str(tmp_path / "state"),
        "--profile",
        "host-import",
        "--caller",
        "algo-cli",
    ]

    with pytest.raises(
        migrate_host_memory.HostMemoryMigrationError,
        match="confirmation is invalid",
    ):
        migrate_host_memory.run(parser.parse_args([*base, "--confirm", "yes"]))
    with pytest.raises(
        migrate_host_memory.HostMemoryMigrationError,
        match="review-required",
    ):
        migrate_host_memory.run(
            parser.parse_args(
                [
                    *base,
                    "--confirm",
                    migrate_host_memory.IMPORT_CONFIRMATION,
                ]
            )
        )
    with pytest.raises(
        migrate_host_memory.HostMemoryMigrationError,
        match="retirement confirmation is invalid",
    ):
        migrate_host_memory.run(
            parser.parse_args(
                [
                    *base,
                    "--confirm",
                    migrate_host_memory.IMPORT_CONFIRMATION,
                    "--allow-review-required",
                    "--retire-source",
                    "--retire-confirm",
                    "delete it",
                ]
            )
        )

    assert source.exists()
    assert not (tmp_path / "state").exists()


def test_host_memory_migration_imports_short_term_and_verifies_fresh_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "host" / "memory.json"
    state_dir = tmp_path / "state"
    payloads = [
        "Use concise status receipts for completed work.",
        "Protected recall must fail closed instead of using plaintext fallback.",
    ]
    _write_owner_only_host_catalog(source, payloads)
    monkeypatch.setattr(
        migrate_host_memory,
        "OllamaTextEmbedder",
        lambda **_kwargs: _SemanticTestEmbedder(),
    )
    args = migrate_host_memory.build_parser().parse_args(
        [
            "--source",
            str(source),
            "--state-dir",
            str(state_dir),
            "--profile",
            "host-import",
            "--caller",
            "algo-cli",
            "--confirm",
            migrate_host_memory.IMPORT_CONFIRMATION,
        ]
    )

    first = migrate_host_memory.run(args)
    second = migrate_host_memory.run(args)
    receipt_path = source.with_name(f"{source.name}.echo-veil-receipt.json")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    with AgentMemory(
        state_dir,
        profile="host-import",
        embed=_SemanticTestEmbedder(),
    ) as memory:
        records = memory.list_memories(
            limit=10,
            layers=["short_term"],
            topic_prefix="host import · algo-cli · ",
        )

    assert first["mode"] == "confirmed_import"
    assert first["created_records"] == 2
    assert first["duplicate_records"] == 0
    assert first["fresh_process_verified"] is True
    assert first["all_records_shielded"] is True
    assert first["plaintext_export_created"] is False
    assert first["plaintext_source_retired"] is False
    assert second["created_records"] == 0
    assert second["duplicate_records"] == 2
    assert source.exists()
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
    assert receipt["state"] == "verified_source_retained"
    assert receipt["fresh_process_verified"] is True
    assert receipt["plaintext_source_retired"] is False
    assert receipt["retirement_is_secure_erase"] is False
    assert {record["payload"] for record in records} == set(payloads)
    assert all(record["memory_layer"] == "short_term" for record in records)
    assert all(record["layer_contract_protected"] is True for record in records)
    receipt_text = json.dumps(receipt, sort_keys=True)
    assert all(payload not in receipt_text for payload in payloads)
    assert str(source) not in receipt_text


def test_host_memory_migration_retires_only_after_verified_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "host" / "memory.json"
    state_dir = tmp_path / "state"
    payload = "The reviewed host memory belongs in protected Short-Term."
    _write_owner_only_host_catalog(source, [payload])
    monkeypatch.setattr(
        migrate_host_memory,
        "OllamaTextEmbedder",
        lambda **_kwargs: _SemanticTestEmbedder(),
    )
    args = migrate_host_memory.build_parser().parse_args(
        [
            "--source",
            str(source),
            "--state-dir",
            str(state_dir),
            "--profile",
            "retired-import",
            "--caller",
            "algo-cli",
            "--confirm",
            migrate_host_memory.IMPORT_CONFIRMATION,
            "--retire-source",
            "--retire-confirm",
            migrate_host_memory.RETIRE_CONFIRMATION,
        ]
    )

    report = migrate_host_memory.run(args)
    receipt_path = source.with_name(f"{source.name}.echo-veil-receipt.json")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    with AgentMemory(
        state_dir,
        profile="retired-import",
        embed=_SemanticTestEmbedder(),
    ) as memory:
        protected = memory.list_memories(
            limit=10,
            layers=["short_term"],
            topic_prefix="host import · algo-cli · ",
        )

    assert report["fresh_process_verified"] is True
    assert report["plaintext_source_retired"] is True
    assert report["retirement_is_secure_erase"] is False
    assert not source.exists()
    assert receipt["state"] == "retired"
    assert receipt["plaintext_source_retired"] is True
    assert [record["payload"] for record in protected] == [payload]


def test_host_memory_migration_failure_retains_plaintext_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "host" / "memory.json"
    _write_owner_only_host_catalog(
        source,
        ["Keep the source when the semantic embedding service is unavailable."],
    )

    class BrokenEmbedder:
        def __init__(self, **_kwargs: object) -> None:
            raise RuntimeError("synthetic private detail")

    monkeypatch.setattr(
        migrate_host_memory,
        "OllamaTextEmbedder",
        BrokenEmbedder,
    )
    args = migrate_host_memory.build_parser().parse_args(
        [
            "--source",
            str(source),
            "--state-dir",
            str(tmp_path / "state"),
            "--profile",
            "failed-import",
            "--caller",
            "algo-cli",
            "--confirm",
            migrate_host_memory.IMPORT_CONFIRMATION,
        ]
    )

    with pytest.raises(
        migrate_host_memory.HostMemoryMigrationError,
        match="embedding service is unavailable",
    ) as failure:
        migrate_host_memory.run(args)

    assert "synthetic private detail" not in str(failure.value)
    assert source.exists()
    assert not source.with_name(f"{source.name}.echo-veil-receipt.json").exists()


def test_host_memory_migration_rolls_back_partial_write_before_releasing_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "host" / "memory.json"
    _write_owner_only_host_catalog(
        source,
        [
            "First reviewed seed crystal.",
            "Second reviewed seed crystal.",
        ],
    )
    lifecycle: list[str] = []

    class FakeMemory:
        active = False
        writes = 0

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> "FakeMemory":
            self.active = True
            lifecycle.append("entered")
            return self

        def __exit__(self, *_args: object) -> None:
            self.active = False
            lifecycle.append("exited")

        def remember(
            self,
            _topic: str,
            _payload: str,
            **_kwargs: object,
        ) -> dict[str, object]:
            assert self.active
            self.writes += 1
            if self.writes == 2:
                raise RuntimeError("synthetic second-write failure")
            lifecycle.append("created")
            return {"created": True, "vine_id": "first-created"}

        def forget(self, vine_id: str) -> dict[str, object]:
            assert self.active
            lifecycle.append(f"forgot:{vine_id}")
            return {"forgotten": True}

    monkeypatch.setattr(
        migrate_host_memory,
        "OllamaTextEmbedder",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(migrate_host_memory, "AgentMemory", FakeMemory)
    args = migrate_host_memory.build_parser().parse_args(
        [
            "--source",
            str(source),
            "--state-dir",
            str(tmp_path / "state"),
            "--profile",
            "partial-import",
            "--caller",
            "algo-cli",
            "--confirm",
            migrate_host_memory.IMPORT_CONFIRMATION,
        ]
    )

    with pytest.raises(
        migrate_host_memory.HostMemoryMigrationError,
        match="protected host-memory import failed",
    ):
        migrate_host_memory.run(args)

    assert lifecycle == [
        "entered",
        "created",
        "forgot:first-created",
        "exited",
    ]
    assert source.exists()


def test_host_memory_migration_rejects_symlink_path_components(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("symlink creation is not reliably available on Windows")
    real = tmp_path / "real"
    source = real / "memory.json"
    _write_owner_only_host_catalog(source, ["Reviewed seed crystal."])
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    args = migrate_host_memory.build_parser().parse_args(
        [
            "--source",
            str(linked / "memory.json"),
            "--caller",
            "algo-cli",
        ]
    )

    with pytest.raises(
        migrate_host_memory.HostMemoryMigrationError,
        match="symlink components",
    ):
        migrate_host_memory.run(args)

    assert source.exists()


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
        "layer_contract_wired": True,
        "context_trace_wired": True,
        "competing_memory_wired": True,
        "content_policy_wired": True,
        "live_refresh_wired": True,
        "preflight_receipt_wired": True,
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
    assert report["retrieval"]["competing_memory"] == (
        "possible-conflict-no-inference-v1"
    )
    assert report["memory_layers"]["all_records_shielded"] is True
    assert report["memory_layers"]["competing_memory"] == (
        "bounded-authenticated-topic-v1"
    )
    assert report["memory_layers"]["content_policy"] == "bounded-seed-crystal-v1"
    assert report["memory_layers"]["payload_limits_chars"] == {
        "live": 20_000,
        "short_term": 12_000,
        "long_term": 2_000,
        "contextual_logic": 4_000,
    }
    assert report["memory_layers"]["automatic_content_rewriting"] is False
    assert report["memory_layers"]["live_refresh"] == (
        "protected-supersession-or-renewal-v1"
    )
    assert report["memory_layers"]["unprotected_record_count"] == 0
    assert report["memory_layers"]["semantic_layers"] == [
        "live",
        "short_term",
        "long_term",
        "contextual_logic",
    ]
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


def test_layer_feature_marker_is_authenticated_by_profile_scope(
    tmp_path: Path,
) -> None:
    scope = "workspace:feature-binding"
    with AgentMemory(tmp_path, scope=scope):
        pass

    manifest_path = tmp_path / "default" / "keyring.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["features"] == [
        "record-integrity-hmac-v1",
        "shielded-four-layer-v1",
    ]
    del manifest["features"]
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)

    with pytest.raises(PermissionError, match="scope"):
        AgentMemory(tmp_path, scope=scope)


def test_corrupt_record_is_quarantined_without_hiding_healthy_records(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, scope="workspace:quarantine") as memory:
        corrupt = memory.remember("alpha recovery", "Use the alpha recovery path.")
        healthy = memory.remember("beta recovery", "Use the beta recovery path.")

    connection = sqlite3.connect(tmp_path / "default" / "payloads.db")
    try:
        row = connection.execute(
            "SELECT ciphertext FROM payloads WHERE vine_id = ?",
            (corrupt["vine_id"],),
        ).fetchone()
        assert row is not None
        ciphertext = bytes(row[0])
        tampered = ciphertext[:-1] + bytes((ciphertext[-1] ^ 1,))
        connection.execute(
            "UPDATE payloads SET ciphertext = ? WHERE vine_id = ?",
            (tampered, corrupt["vine_id"]),
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


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE payloads SET effective_at = effective_at + 1 WHERE vine_id = ?",
        "UPDATE payloads SET superseded_by = 'forged-record' WHERE vine_id = ?",
        "UPDATE memory_terms SET term_count = term_count + 1 WHERE vine_id = ?",
    ],
)
def test_authenticated_lifecycle_and_term_tampering_is_quarantined(
    tmp_path: Path,
    statement: str,
) -> None:
    with AgentMemory(tmp_path, scope="workspace:metadata-auth") as memory:
        created = memory.remember(
            "authenticated policy",
            "The protected policy remains bound to its lifecycle metadata.",
        )

    connection = sqlite3.connect(tmp_path / "default" / "payloads.db")
    try:
        connection.execute(statement, (created["vine_id"],))
        connection.commit()
    finally:
        connection.close()

    with AgentMemory(tmp_path, scope="workspace:metadata-auth") as memory:
        report = memory.doctor()
        recalled = memory.recall("authenticated protected policy")

    assert report["adapter_ready"] is False
    assert report["quarantined_records"] == 1
    assert recalled["results"] == []


def test_tombstone_authentication_is_verified_on_every_open(tmp_path: Path) -> None:
    scope = "workspace:tombstone-auth"
    with AgentMemory(tmp_path, scope=scope) as memory:
        created = memory.remember("deletion marker", "Delete this protected record.")
        memory.forget(str(created["vine_id"]))

    connection = sqlite3.connect(tmp_path / "default" / "payloads.db")
    try:
        connection.execute("UPDATE deletion_tombstones SET deleted_at = deleted_at + 1")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="authenticated deletion state"):
        AgentMemory(tmp_path, scope=scope)


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


def test_key_readers_use_binary_noninheritable_windows_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_key = tmp_path / "profile.key"
    legacy_key = tmp_path / "agent.key"
    binary_flag = 1 << 26
    noninheritable_flag = 1 << 27
    adversarial_key = b"\x1a\r\n" + bytes(range(29))
    opened: list[tuple[Path, int]] = []
    closed: list[int] = []

    class _RegularFile:
        st_mode = stat.S_IFREG

    def open_key(path: Path, flags: int) -> int:
        opened.append((path, flags))
        return 73 + len(opened)

    def read_key(_descriptor: int, maximum: int) -> bytes:
        assert maximum == 33
        assert opened[-1][1] & binary_flag
        assert opened[-1][1] & noninheritable_flag
        return adversarial_key

    monkeypatch.setattr(agent_security.os, "name", "nt")
    monkeypatch.setattr(agent_security.os, "O_BINARY", binary_flag, raising=False)
    monkeypatch.setattr(
        agent_security.os,
        "O_NOINHERIT",
        noninheritable_flag,
        raising=False,
    )
    monkeypatch.setattr(agent_security, "_require_owner_file", lambda *_args: None)
    monkeypatch.setattr(
        agent_memory_module,
        "_require_secure_regular_file",
        lambda *_args: None,
    )
    monkeypatch.setattr(agent_security.os, "open", open_key)
    monkeypatch.setattr(agent_security.os, "fstat", lambda _descriptor: _RegularFile())
    monkeypatch.setattr(agent_security.os, "read", read_key)
    monkeypatch.setattr(
        agent_security.os,
        "fchmod",
        lambda _descriptor, _mode: None,
        raising=False,
    )
    monkeypatch.setattr(
        agent_security.os,
        "close",
        lambda descriptor: closed.append(descriptor),
    )

    assert agent_security._read_key(profile_key) == adversarial_key
    assert agent_memory_module._load_existing_key(legacy_key) == adversarial_key
    assert [path for path, _flags in opened] == [profile_key, legacy_key]
    assert len(closed) == 2


@pytest.mark.parametrize("missing_flag", ("O_BINARY", "O_NOINHERIT"))
def test_windows_key_read_flags_fail_closed_without_binary_crt_support(
    monkeypatch: pytest.MonkeyPatch,
    missing_flag: str,
) -> None:
    monkeypatch.setattr(agent_security.os, "name", "nt")
    monkeypatch.setattr(agent_security.os, "O_BINARY", 1 << 26, raising=False)
    monkeypatch.setattr(agent_security.os, "O_NOINHERIT", 1 << 27, raising=False)
    monkeypatch.delattr(agent_security.os, missing_flag)

    with pytest.raises(OSError, match="binary non-inheritable"):
        agent_security._binary_noninheritable_read_flags()


@pytest.mark.skipif(os.name != "nt", reason="Windows native binary CRT contract")
def test_windows_native_key_reads_preserve_ctrl_z_and_crlf_bytes(
    tmp_path: Path,
) -> None:
    key_directory = agent_security._secure_directory(tmp_path / "binary-key-profile")
    key_path = key_directory / "agent.key"
    adversarial_key = b"\x1a\r\n" + bytes(range(29))
    agent_security._write_new_key(key_path, adversarial_key)

    assert agent_security._read_key(key_path) == adversarial_key
    assert agent_memory_module._load_existing_key(key_path) == adversarial_key


def test_windows_manifest_write_uses_private_stage_and_write_through_move(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "keyring.json"
    encoded = b'{"active_key_id":"ev-0000000000000000"}'
    created_state = agent_security._WindowsFileState(
        identity=(1, 2, stat.S_IFREG, 1, 0),
        owner=b"owner",
        dacl=b"private-dacl",
    )
    staged_state = agent_security._WindowsFileState(
        identity=created_state.identity,
        owner=created_state.owner,
        dacl=created_state.dacl,
    )
    events: list[str] = []
    real_open = os.open

    class _ParentGuard:
        def __enter__(self) -> tuple[()]:
            events.append("parent-chain-enter")
            return ()

        def __exit__(self, *_args: object) -> None:
            events.append("parent-chain-exit")

    def create_private(path: Path) -> tuple[int, agent_security._WindowsFileState]:
        events.append("private-create")
        return real_open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600), created_state

    def write_all(descriptor: int, value: bytes) -> None:
        events.append("binary-write")
        assert os.write(descriptor, value) == len(value)

    def fsync(_descriptor: int) -> None:
        events.append("file-fsync")

    def verify_stage(
        descriptor: int,
        path: Path,
        *,
        expected_payload: bytes,
        expected_state: agent_security._WindowsFileState,
    ) -> agent_security._WindowsFileState:
        events.append("stage-verify")
        assert expected_payload == encoded
        assert expected_state == created_state
        assert path.name.startswith(".keyring.json.")
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, len(encoded) + 1) == encoded
        return staged_state

    def move(source: Path, destination: Path) -> None:
        events.append("move-write-through")
        os.replace(source, destination)

    def verify_publication(
        path: Path,
        *,
        expected_payload: bytes,
        expected_state: agent_security._WindowsFileState,
    ) -> None:
        events.append("publication-verify")
        assert path == target
        assert expected_payload == encoded
        assert expected_state == staged_state
        assert path.read_bytes() == encoded

    monkeypatch.setattr(
        agent_security, "_windows_create_private_staging", create_private
    )
    monkeypatch.setattr(
        agent_security,
        "_windows_pinned_directory_chain",
        lambda path: (
            _ParentGuard()
            if path == target.parent
            else pytest.fail("unexpected pinned path")
        ),
    )
    monkeypatch.setattr(agent_security, "_write_all", write_all)
    monkeypatch.setattr(agent_security.os, "fsync", fsync)
    monkeypatch.setattr(agent_security, "_windows_verify_descriptor", verify_stage)
    monkeypatch.setattr(
        agent_security,
        "_windows_move_file_replace_write_through",
        move,
    )
    monkeypatch.setattr(
        agent_security,
        "_windows_verify_publication",
        verify_publication,
    )
    monkeypatch.setattr(
        agent_security.tempfile,
        "mkstemp",
        lambda **_kwargs: pytest.fail("Windows must not use mkstemp"),
    )

    agent_security._atomic_write_json_windows(target, encoded)

    assert events == [
        "parent-chain-enter",
        "private-create",
        "binary-write",
        "file-fsync",
        "stage-verify",
        "move-write-through",
        "publication-verify",
        "parent-chain-exit",
    ]
    assert list(tmp_path.iterdir()) == [target]


def test_windows_manifest_write_cleans_private_stage_when_move_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "keyring.json"
    encoded = b"{}"
    state = agent_security._WindowsFileState(
        identity=(1, 2, stat.S_IFREG, 1, 0),
        owner=b"owner",
        dacl=b"private-dacl",
    )
    real_open = os.open

    def create_private(path: Path) -> tuple[int, agent_security._WindowsFileState]:
        return real_open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600), state

    def verify_stage(
        _descriptor: int,
        _path: Path,
        *,
        expected_payload: bytes,
        expected_state: agent_security._WindowsFileState,
    ) -> agent_security._WindowsFileState:
        assert expected_payload == encoded
        assert expected_state == state
        return state

    monkeypatch.setattr(
        agent_security, "_windows_create_private_staging", create_private
    )
    monkeypatch.setattr(agent_security, "_windows_verify_descriptor", verify_stage)
    monkeypatch.setattr(
        agent_security,
        "_windows_move_file_replace_write_through",
        lambda _source, _destination: (_ for _ in ()).throw(
            OSError("synthetic write-through move failure")
        ),
    )

    with pytest.raises(OSError, match="write-through move"):
        agent_security._atomic_write_json_windows(target, encoded)

    assert list(tmp_path.iterdir()) == []


def test_atomic_json_dispatch_never_enters_posix_tail_on_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "keyring.json"
    calls: list[tuple[Path, bytes]] = []
    monkeypatch.setattr(agent_security.os, "name", "nt")
    monkeypatch.setattr(
        agent_security,
        "_atomic_write_json_windows",
        lambda path, encoded: calls.append((path, encoded)),
    )
    monkeypatch.setattr(
        agent_security.tempfile,
        "mkstemp",
        lambda **_kwargs: pytest.fail("Windows must not use mkstemp"),
    )

    agent_security._atomic_write_json(target, {"version": 1})

    assert calls == [(target, b'{"version":1}')]


def test_windows_private_directory_rechecks_leaf_inside_final_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _ChainGuard:
        def __enter__(self) -> tuple[()]:
            events.append("chain-enter")
            return ()

        def __exit__(self, *_args: object) -> None:
            events.append("chain-exit")

    monkeypatch.setattr(agent_security.os, "name", "nt")
    monkeypatch.setattr(agent_security, "Path", type(tmp_path))
    monkeypatch.setattr(
        agent_security,
        "_windows_verify_private_directory",
        lambda _path: events.append("leaf-verify"),
    )
    monkeypatch.setattr(
        agent_security,
        "_windows_pinned_directory_chain",
        lambda _path: _ChainGuard(),
    )

    assert agent_security._windows_ensure_private_directory(tmp_path) == tmp_path
    assert events == ["leaf-verify", "chain-enter", "leaf-verify", "chain-exit"]


def test_payload_version_rejects_unsafe_windows_sidecar_before_sqlite_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload_database = tmp_path / "payloads.db"
    payload_database.touch()
    calls: list[str] = []
    monkeypatch.setattr(
        agent_memory_module,
        "_require_secure_regular_file",
        lambda _path, _label: calls.append("main-file-verified"),
    )

    def reject_sidecar(_path: Path) -> None:
        calls.append("sidecar-rejected")
        raise OSError("unsafe stale Windows SQLite sidecar")

    monkeypatch.setattr(
        agent_memory_module,
        "_windows_verify_private_sqlite_sidecars",
        reject_sidecar,
    )
    monkeypatch.setattr(
        agent_memory_module.sqlite3,
        "connect",
        lambda *_args, **_kwargs: pytest.fail(
            "SQLite must not open before stale sidecar validation"
        ),
    )

    with pytest.raises(OSError, match="unsafe stale"):
        agent_memory_module._payload_database_version(payload_database)

    assert calls == ["main-file-verified", "sidecar-rejected"]


def test_windows_move_uses_replace_and_write_through_without_copy_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str, int]] = []

    class _NativeCall:
        argtypes: object = None
        restype: object = None

        def __call__(self, source: str, destination: str, flags: int) -> bool:
            calls.append((source, destination, flags))
            return True

    class _Kernel32:
        MoveFileExW = _NativeCall()

    import ctypes

    monkeypatch.setattr(agent_security.os, "name", "nt")
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda *_args, **_kwargs: _Kernel32(), raising=False
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)
    monkeypatch.setattr(ctypes, "WinError", OSError, raising=False)
    source = tmp_path / "source"
    destination = tmp_path / "destination"

    agent_security._windows_move_file_replace_write_through(source, destination)

    assert calls == [
        (os.fspath(source), os.fspath(destination), 0x00000001 | 0x00000008)
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows native collision contract")
def test_windows_private_create_collision_preserves_existing_bytes(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "existing.db"
    sentinel = b"pre-existing sentinel bytes"
    existing.write_bytes(sentinel)

    with pytest.raises(FileExistsError):
        agent_security._windows_create_private_staging(existing)

    assert existing.read_bytes() == sentinel


@pytest.mark.skipif(os.name != "nt", reason="Windows native DACL migration contract")
def test_windows_current_user_directory_is_canonicalized_to_private_dacl(
    tmp_path: Path,
) -> None:
    inherited = tmp_path / "inherited-directory"
    inherited.mkdir()

    assert agent_security._windows_ensure_private_directory(inherited) == inherited
    agent_security._windows_verify_private_directory(inherited)


@pytest.mark.skipif(os.name != "nt", reason="Windows native ACL/rename contract")
def test_windows_native_manifest_publication_preserves_exact_private_state(
    tmp_path: Path,
) -> None:
    target = tmp_path / "keyring.json"
    first = {"version": 1, "active_key_id": "ev-0000000000000000"}
    second = {"version": 1, "active_key_id": "ev-1111111111111111"}

    agent_security._atomic_write_json(target, first)
    descriptor = os.open(
        target,
        os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
    )
    try:
        first_state = agent_security._windows_verify_descriptor(
            descriptor,
            target,
            expected_payload=json.dumps(
                first,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
    finally:
        os.close(descriptor)

    agent_security._atomic_write_json(target, second)
    descriptor = os.open(
        target,
        os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
    )
    try:
        second_state = agent_security._windows_verify_descriptor(
            descriptor,
            target,
            expected_payload=json.dumps(
                second,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
    finally:
        os.close(descriptor)

    assert (first_state.owner, first_state.dacl) == (
        second_state.owner,
        second_state.dacl,
    )
    assert target.stat().st_nlink == 1
    assert not any(path.suffix == ".tmp" for path in tmp_path.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="Windows native reparse-point contract")
def test_windows_native_manifest_write_rejects_reparse_target(tmp_path: Path) -> None:
    victim = tmp_path / "victim.json"
    victim.write_text("unchanged", encoding="utf-8")
    target = tmp_path / "keyring.json"
    try:
        target.symlink_to(victim)
    except OSError:
        pytest.skip("symlink creation is unavailable for this Windows account")

    with pytest.raises(ValueError, match="symbolic links"):
        agent_security._atomic_write_json(target, {"version": 1})

    assert victim.read_text(encoding="utf-8") == "unchanged"


@pytest.mark.skipif(os.name != "nt", reason="Windows native ancestry contract")
def test_windows_private_directory_rejects_existing_leaf_below_reparse_ancestor(
    tmp_path: Path,
) -> None:
    real_parent = agent_security._windows_ensure_private_directory(
        tmp_path / "real-parent"
    )
    agent_security._windows_ensure_private_directory(real_parent / "private-leaf")
    redirected_parent = tmp_path / "redirected-parent"
    try:
        redirected_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip(
            "directory symlink creation is unavailable for this Windows account"
        )

    with pytest.raises(OSError, match="directory|ancestry|path"):
        agent_security._windows_ensure_private_directory(
            redirected_parent / "private-leaf"
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows native at-rest DACL contract")
def test_windows_native_agent_memory_files_and_sqlite_sidecars_are_private(
    tmp_path: Path,
) -> None:
    sidecars: set[str] = set()
    with AgentMemory(tmp_path, scope="workspace:windows-at-rest") as memory:
        memory.remember("private Windows state", "Keep this payload protected.")
        profile = tmp_path / "default"
        for path in profile.glob("*.db-*"):
            descriptor = os.open(
                path,
                os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
            )
            try:
                agent_security._windows_verify_descriptor(
                    descriptor,
                    path,
                    expected_payload=None,
                    require_protected_security=False,
                )
                assert agent_security._windows_descriptor_private_dacl_is_safe(
                    descriptor
                )
            finally:
                os.close(descriptor)
            sidecars.add(path.name)

    profile = tmp_path / "default"
    agent_security._windows_verify_private_directory(profile)
    agent_security._windows_verify_private_directory(profile / "keys")
    assert {"echo-veil.db-shm", "echo-veil.db-wal"} <= sidecars
    assert {"payloads.db-shm", "payloads.db-wal"} <= sidecars
    explicit_private_files = {
        profile / "echo-veil.db",
        profile / "keyring.json",
        profile / "payloads.db",
        profile / "profile-lock.db",
        *tuple((profile / "keys").glob("*.key")),
    }
    expected_security = agent_security._windows_expected_private_security()
    for path in explicit_private_files:
        descriptor = agent_security._windows_open_private_file(
            path,
            writable=False,
        )
        try:
            agent_security._windows_verify_descriptor(
                descriptor,
                path,
                expected_payload=None,
                expected_security=expected_security,
            )
        finally:
            os.close(descriptor)


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
            memory.remember(
                f"rotation topic {index}",
                f"rotation payload {index}",
                provenance=[f"rotation:record-{index}"],
            )
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
            assert recalled["results"][0]["provenance"] == [f"rotation:record-{index}"]
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

        memory.recall(f"{first_topic}\n{first_payload}", mutate_lifecycle=True)
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
        "echo_veil_refresh_live",
        "echo_veil_promote",
        "echo_veil_recall",
        "echo_veil_context",
        "echo_veil_forget",
        "echo_veil_list",
        "echo_veil_doctor",
        "echo_veil_reindex",
        "echo_veil_rotate_key",
        "echo_veil_retire_key",
    ]

    with AgentMemory(tmp_path) as memory:
        server = McpServer(memory, caller="codex")
        initialized = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "1900-01-01"},
            }
        )
        listed = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        hidden_rotation = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {
                    "name": "echo_veil_rotate_key",
                    "arguments": {"confirm": True},
                },
            }
        )
        operator_listed = McpServer(
            memory,
            caller="operator",
            operator_tools=True,
        ).handle({"jsonrpc": "2.0", "id": 22, "method": "tools/list"})
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
        assert remembered is not None
        promoted = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/call",
                "params": {
                    "name": "echo_veil_promote",
                    "arguments": {
                        "vine_id": remembered["result"]["structuredContent"]["vine_id"],
                        "target_layer": "long_term",
                        "reason": "The schedule was explicitly confirmed.",
                        "provenance": ["user:explicit"],
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
    assert len(listed["result"]["tools"]) == 9
    assert {tool["name"] for tool in listed["result"]["tools"]}.isdisjoint(
        {"echo_veil_rotate_key", "echo_veil_retire_key"}
    )
    assert hidden_rotation is not None
    assert hidden_rotation["result"]["isError"] is True
    assert operator_listed is not None
    assert len(operator_listed["result"]["tools"]) == 11
    recall_tool = next(
        tool for tool in listed["result"]["tools"] if tool["name"] == "echo_veil_recall"
    )
    context_tool = next(
        tool
        for tool in listed["result"]["tools"]
        if tool["name"] == "echo_veil_context"
    )
    remember_tool = next(
        tool
        for tool in listed["result"]["tools"]
        if tool["name"] == "echo_veil_remember"
    )
    refresh_tool = next(
        tool
        for tool in listed["result"]["tools"]
        if tool["name"] == "echo_veil_refresh_live"
    )
    assert recall_tool["inputSchema"]["properties"]["top_k"]["minimum"] == 2
    assert recall_tool["inputSchema"]["properties"]["layers"]["maxItems"] == 4
    assert context_tool["inputSchema"]["properties"]["max_depth"]["maximum"] == 2
    assert context_tool["inputSchema"]["properties"]["max_records"]["maximum"] == 20
    assert remember_tool["inputSchema"]["properties"]["payload"]["maxLength"] == 20_000
    assert remember_tool["inputSchema"]["properties"]["provenance"]["maxItems"] == 3
    assert refresh_tool["inputSchema"]["properties"]["payload"]["maxLength"] == 20_000
    assert (
        "long_term" not in (remember_tool["inputSchema"]["properties"]["layer"]["enum"])
    )
    assert "not semantic or authoritative" in initialized["result"]["instructions"]
    assert (
        "seed crystals rather than transcripts"
        in (initialized["result"]["instructions"])
    )
    assert remembered is not None
    assert remembered["result"]["isError"] is False
    assert remembered["result"]["structuredContent"]["created"] is True
    assert remembered["result"]["structuredContent"]["provenance"] == ["caller:codex"]
    assert promoted is not None
    assert promoted["result"]["isError"] is False
    assert promoted["result"]["structuredContent"]["memory_layer"] == "long_term"
    assert refused_reindex is not None
    assert refused_reindex["result"]["isError"] is True
    assert reindexed is not None
    assert reindexed["result"]["isError"] is False
    assert reindexed["result"]["structuredContent"]["reindexed"] == 1


def test_mcp_factories_share_one_profile_without_lifetime_writer_lease(
    tmp_path: Path,
) -> None:
    opened = 0

    def factory() -> AgentMemory:
        nonlocal opened
        opened += 1
        return AgentMemory(
            tmp_path,
            profile="universal-qwen3-test",
            scope="local-user",
            profile_lock_timeout_seconds=0.1,
        )

    codex = McpServer(memory_factory=factory, caller="codex")
    claude = McpServer(memory_factory=factory, caller="claude-code")

    initialized = codex.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    listed = claude.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )
    assert initialized is not None
    assert listed is not None
    assert opened == 0

    remembered = codex.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "echo_veil_remember",
                "arguments": {
                    "topic": "shared local authority",
                    "payload": "Cobalt meadow is the shared continuity marker.",
                    "provenance": ["user:explicit"],
                },
            },
        }
    )
    assert remembered is not None
    assert remembered["result"]["isError"] is False
    assert opened == 1

    recalled = claude.handle(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "echo_veil_recall",
                "arguments": {"query": "cobalt meadow continuity marker"},
            },
        }
    )
    assert recalled is not None
    assert recalled["result"]["isError"] is False
    result = recalled["result"]["structuredContent"]["results"][0]
    assert result["payload"] == "Cobalt meadow is the shared continuity marker."
    assert result["provenance"] == ["caller:codex", "user:explicit"]
    assert opened == 2

    doctor = claude.handle(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "echo_veil_doctor", "arguments": {}},
        }
    )
    assert doctor is not None
    readiness = doctor["result"]["structuredContent"]
    assert readiness["mcp_profile_lease"] == "per-tool-call"
    assert readiness["shared_profile_safe"] is True
    assert readiness["mcp_tool_profile"] == "agent"
    assert opened == 3

    # A third writer can open immediately after both long-lived transport
    # objects have completed their calls. Neither server retains the lease.
    with AgentMemory(
        tmp_path,
        profile="universal-qwen3-test",
        scope="local-user",
        profile_lock_timeout_seconds=0.01,
    ) as direct:
        assert direct.doctor()["writer_serialization"] == "profile-sqlite-lease"


def test_mcp_server_requires_exactly_one_memory_source(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        McpServer()
    with AgentMemory(tmp_path) as memory:
        with pytest.raises(ValueError, match="exactly one"):
            McpServer(memory, memory_factory=lambda: memory)


def test_caller_identity_is_provenance_but_not_promotion_evidence(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path) as memory:
        server = McpServer(memory, caller="claude-code")
        remembered = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "echo_veil_remember",
                    "arguments": {
                        "topic": "deployment decision",
                        "payload": "The deployment decision remains provisional.",
                    },
                },
            }
        )
        assert remembered is not None
        vine_id = remembered["result"]["structuredContent"]["vine_id"]
        refused = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "echo_veil_promote",
                    "arguments": {
                        "vine_id": vine_id,
                        "target_layer": "long_term",
                        "reason": "A caller identity alone must not harden memory.",
                    },
                },
            }
        )

    assert remembered["result"]["structuredContent"]["provenance"] == [
        "caller:claude-code"
    ]
    assert refused is not None
    assert refused["result"]["isError"] is True
    assert "durable provenance" in refused["result"]["structuredContent"]["message"]


def test_caller_attribution_is_bounded_and_cannot_be_path_shaped(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path) as memory:
        with pytest.raises(ValueError, match="caller"):
            McpServer(memory, caller="../another-host")

        server = McpServer(memory, caller="codex")
        refused = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "echo_veil_remember",
                    "arguments": {
                        "topic": "bounded provenance",
                        "payload": "The transport reserves one provenance slot.",
                        "provenance": [
                            "source:one",
                            "source:two",
                            "source:three",
                            "source:four",
                        ],
                    },
                },
            }
        )

    assert refused is not None
    assert refused["result"]["isError"] is True
    assert "at most 3 supplied" in refused["result"]["structuredContent"]["message"]


def test_rpc_recall_preserves_ambiguous_pair_when_one_result_requested(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        memory.remember("first policy", "The first policy applies.")
        memory.remember("second policy", "The second policy applies.")

        recalled = dispatch(
            memory,
            "recall",
            {"query": "Which rule applies?", "top_k": 1},
        )

    assert len(recalled["results"]) == 2
    assert recalled["ranking_ambiguous"] is True
    assert recalled["requested_top_k"] == 1
    assert recalled["effective_top_k"] == 2
    assert recalled["ambiguity_candidates_preserved"] is True


def test_rpc_recall_preserves_competing_pair_when_one_result_requested(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        first = memory.remember("routing fact", "Use route alpha.")
        second = memory.remember("routing fact", "Use route beta.")

        recalled = dispatch(
            memory,
            "recall",
            {"query": "Which routing fact applies?", "top_k": 1},
        )

    assert {item["vine_id"] for item in recalled["results"]} == {
        first["vine_id"],
        second["vine_id"],
    }
    assert recalled["requested_top_k"] == 1
    assert recalled["effective_top_k"] == 2
    assert recalled["competing_memory_detected"] is True
    assert recalled["competing_candidates_preserved"] is True
    assert recalled["ranking_ambiguous"] is False


def test_rpc_refreshes_live_memory_with_protected_supersession(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        original = memory.remember(
            "active build",
            "The build is running.",
            layer="live",
            provenance=["agent:build-loop"],
        )
        refreshed = dispatch(
            memory,
            "echo_veil_refresh_live",
            {
                "vine_id": original["vine_id"],
                "payload": "The build passed.",
                "provenance": ["receipt:build-pass"],
            },
        )

    assert refreshed["previous_vine_id"] == original["vine_id"]
    assert refreshed["vine_id"] != original["vine_id"]
    assert refreshed["supersedes"] == [original["vine_id"]]
    assert refreshed["memory_layer"] == "live"
    assert refreshed["content_policy"]["policy"] == "bounded-seed-crystal-v1"


def test_rpc_exposes_layer_scoped_recall_and_protected_context(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticTestEmbedder()) as memory:
        evidence = memory.remember("decision evidence", "The evidence is verified.")
        logic = memory.remember(
            "verified decision",
            "The decision follows the verified evidence.",
            layer="contextual_logic",
            provenance=["decision:verified"],
            promotion_reason="The linked evidence was verified.",
            logic_kind="decision",
            related_ids=[str(evidence["vine_id"])],
        )

        recalled = dispatch(
            memory,
            "recall",
            {
                "query": "Which decision follows?",
                "layers": ["contextual_logic"],
            },
        )
        traced = dispatch(
            memory,
            "context",
            {
                "query": "Why does the verified decision follow?",
                "max_depth": 1,
                "max_records": 8,
            },
        )

    assert recalled["requested_layers"] == ["contextual_logic"]
    assert recalled["results"][0]["vine_id"] == logic["vine_id"]
    assert traced["logic_roots"][0]["vine_id"] == logic["vine_id"]
    assert traced["evidence"][0]["vine_id"] == evidence["vine_id"]


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
