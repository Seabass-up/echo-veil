from __future__ import annotations

from pathlib import Path

from examples.agent_memory import ApplicationMemory, demo_embedding, run_demo


ROOT = Path(__file__).resolve().parents[1]


def test_runnable_agent_example_retrieves_and_gates_memory() -> None:
    result = run_demo()

    assert result.topic == "Topping Avenue service estimate labor rate"
    assert result.payload == "The approved labor rate is 125 dollars per hour."
    assert result.confidence_band == "solid_vine_integration"
    assert result.score >= 0.85


def test_agent_adapter_returns_none_when_no_memory_remains_active() -> None:
    memory = ApplicationMemory(demo_embedding)

    assert memory.recall("family schedule") is None


def test_repository_and_runtime_agent_guides_are_linked() -> None:
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    integration = (ROOT / "docs" / "AGENT_INTEGRATION.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "docs/AGENT_INTEGRATION.md" in agents
    assert "examples/agent_memory.py" in integration
    assert "docs/AGENT_INTEGRATION.md" in readme
