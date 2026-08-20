#!/usr/bin/env python3
"""Exercise the actual v0.7 Python and Hermes response consumers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from echo_veil.agent_preflight import assert_doctor_ready, build_preflight_context
from integrations.hermes import plugin as hermes_plugin


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    assert bundle["schema"] == "echo-veil-n-minus-one-bundle-v1"
    for state in bundle["states"]:
        assert_doctor_ready(
            state["doctor"],
            expected_profile="echo-universal-qwen3-v1",
            expected_model="qwen3-embedding:latest",
            expected_dimension=1024,
        )
        for host in ("aip", "claude-code", "codex", "droid"):
            context = build_preflight_context(host, state["pi_recall"])
            assert context.startswith("ECHO VEIL REQUIRED MEMORY PREFLIGHT")
            assert "record_envelope" not in context
            assert "record-envelope" not in context
        hermes_context = hermes_plugin._validate_preflight(
            state["legacy_preflight"]["hermes"]
        )
        assert hermes_context.startswith("ECHO VEIL REQUIRED MEMORY PREFLIGHT")
        assert "record_envelope" not in hermes_context
        assert "record-envelope" not in hermes_context
    print(
        json.dumps(
            {
                "consumers": ["aip", "claude-code", "codex", "droid", "hermes"],
                "schema": "echo-veil-n-minus-one-python-probe-v1",
                "states": ["mixed-v2-v3", "fully-v3"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
