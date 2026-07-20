from __future__ import annotations

from io import BytesIO
from pathlib import Path

import numpy as np
import pytest

from echo_veil.agent_cli import MAX_REQUEST_BYTES, McpServer, TOOLS, _read_mcp_line
from echo_veil.agent_memory import AgentMemory, HashingTextEmbedder


def test_hashing_embedder_is_stable_and_keyword_oriented() -> None:
    embed = HashingTextEmbedder(128)

    first = embed("Riverside labor rate estimate")
    repeated = embed("Riverside labor rate estimate")
    related = embed("labor rate")
    unrelated = embed("school pickup schedule")

    assert np.array_equal(first, repeated)
    assert float(first @ related) > float(first @ unrelated)
    assert np.linalg.norm(first) == pytest.approx(1.0)


def test_agent_memory_persists_deduplicates_recalls_and_forgets(tmp_path: Path) -> None:
    topic = "Riverside service estimate labor rate"
    payload = "The approved labor rate is 125 dollars per hour."
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
    first_topic = "Riverside labor estimate"
    first_payload = "Riverside estimate uses a 125 dollar labor rate."
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

    assert initialized is not None
    assert initialized["result"]["protocolVersion"] == "2025-11-25"
    assert initialized["result"]["serverInfo"]["name"] == "echo-veil"
    assert listed is not None
    assert len(listed["result"]["tools"]) == 4
    assert remembered is not None
    assert remembered["result"]["isError"] is False
    assert remembered["result"]["structuredContent"]["created"] is True


def test_mcp_line_reader_bounds_and_drains_oversized_requests() -> None:
    stream = BytesIO(b"x" * (MAX_REQUEST_BYTES + 50) + b"\n{}\n")

    first, oversized = _read_mcp_line(stream)
    second, second_oversized = _read_mcp_line(stream)

    assert len(first) == MAX_REQUEST_BYTES + 1
    assert oversized is True
    assert second == b"{}\n"
    assert second_oversized is False
