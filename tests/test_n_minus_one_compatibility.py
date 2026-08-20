from __future__ import annotations

import json
from pathlib import Path
import re

from scripts.verify_n_minus_one_consumers import (
    BUNDLE_SCHEMA,
    build_bundle,
    load_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def test_n_minus_one_manifest_pins_every_owned_consumer_class() -> None:
    manifest = load_manifest()
    assert manifest["release"] == "0.7.0"
    assert set(manifest["consumers"]) == {
        "aip",
        "algo-cli",
        "claude-code",
        "codex",
        "droid",
        "goose",
        "hermes",
        "openclaw",
        "opencode",
        "pi",
    }
    assert {
        consumer["qualification"] for consumer in manifest["consumers"].values()
    } == {
        "executed-legacy-consumer",
        "executed-shared-python-consumer",
        "external-release-gate",
        "pinned-policy-wrapper",
        "pinned-thin-wrapper",
    }
    for consumer in manifest["consumers"].values():
        assert consumer["files"]
        for path, digest in consumer["files"].items():
            assert not Path(path).is_absolute()
            assert ".." not in Path(path).parts
            assert _SHA256.fullmatch(digest)


def test_real_mixed_and_v3_profiles_keep_storage_out_of_harness_responses(
    tmp_path: Path,
) -> None:
    bundle = build_bundle(tmp_path / "state")
    assert bundle["schema"] == BUNDLE_SCHEMA
    assert [state["state"] for state in bundle["states"]] == [
        "mixed-v2-v3",
        "fully-v3",
    ]
    assert bundle["invariants"] == load_manifest()["invariants"]
    for state in bundle["states"]:
        assert set(state["legacy_preflight"]) == {
            "aip",
            "claude-code",
            "codex",
            "droid",
            "hermes",
            "openclaw",
            "opencode",
        }
        for response in state["legacy_preflight"].values():
            assert response["preflight_ready"] is True
            assert response["memory_authority"] == "echo-veil"
            assert response["semantic"] is True
            assert "record_envelope" not in response
        assert state["signed_preflight_v2"]["schema"] == ("echo-veil-preflight-v2")
        preflight_json = json.dumps(state["signed_preflight_v2"])
        assert "record_envelope" not in preflight_json
        assert "record-envelope" not in preflight_json
