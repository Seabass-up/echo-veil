from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import verify_host_authority
from scripts.verify_host_authority import (
    DEFAULT_MANIFEST,
    ManifestError,
    artifact_digest,
    audit_authority,
    load_manifest,
    validate_manifest,
    verify_artifact_receipt,
)


ROOT = Path(__file__).resolve().parents[1]
PENDING_HOSTS = {
    "algo-cli",
    "aip",
    "openclaw",
    "hermes",
    "codex",
    "claude-code",
    "pi",
    "opencode",
    "droid",
    "goose",
}


def _manifest() -> dict[str, Any]:
    return load_manifest(DEFAULT_MANIFEST)


@pytest.fixture
def qualified_fixture(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Exercise qualified-state gates without promoting repository evidence."""

    (tmp_path / "shared.txt").write_text("reviewed shared gate\n", encoding="utf-8")
    (tmp_path / "adapter.txt").write_text("reviewed adapter\n", encoding="utf-8")
    return tmp_path, {
        "schema_version": 1,
        "profile": "fixture-profile",
        "scope": "fixture-scope",
        "shared_source_artifacts": ["shared.txt"],
        "shared_source_digest": artifact_digest(tmp_path, ["shared.txt"]),
        "hosts": [
            {
                "id": "aip",
                "display_name": "AIP fixture",
                "adapter": "isolated test adapter",
                "evidence_state": "qualified",
                "qualified_boundary": "fixture only",
                "tested_on": "2026-09-04",
                "tested_version": "1.2.3",
                "source_artifacts": ["adapter.txt"],
                "source_digest": artifact_digest(tmp_path, ["adapter.txt"]),
                "artifact_binding": {
                    "kind": "pep610-wheel-sha256-v1",
                    "distribution": "fixture-host",
                    "version": "1.2.3",
                    "sha256": "a" * 64,
                    "receipt_schema": 1,
                    "memory_contract": "echo-veil-singular-authority-v1",
                    "profile": "fixture-profile",
                    "scope": "fixture-scope",
                    "caller": "aip",
                    "plaintext_fallback": False,
                },
                "checks": ["fixture evidence only"],
                "remaining": ["not installed-host qualification"],
            }
        ],
        "limitations": ["isolated unit-test fixture"],
    }


def _matching_probe(manifest: dict[str, Any]):
    versions = {
        host["id"]: host["tested_version"]
        for host in manifest["hosts"]
        if host["tested_version"] is not None
    }

    def probe(host_id: str) -> dict[str, object]:
        version = versions.get(host_id)
        if version is None:
            return {"status": "not_applicable", "version": None}
        return {"status": "present", "version": version}

    return probe


def _matching_artifact_probe(manifest: dict[str, Any]):
    bindings = {
        host["id"]: host.get("artifact_binding")
        for host in manifest["hosts"]
        if host.get("artifact_binding") is not None
    }

    def probe(host_id: str) -> dict[str, object]:
        binding = bindings.get(host_id)
        if binding is None:
            return {"status": "not_applicable", "receipt": None}
        return {
            "status": "present",
            "receipt": {
                "schema_version": binding["receipt_schema"],
                "distribution": binding["distribution"],
                "version": binding["version"],
                "memory_contract": binding["memory_contract"],
                "profile": binding["profile"],
                "scope": binding["scope"],
                "caller": binding["caller"],
                "plaintext_fallback": False,
                "artifact_bound": True,
                "artifact_sha256": binding["sha256"],
                "installed_source_sha256": "a" * 64,
                "record_integrity": True,
            },
        }

    return probe


def test_authority_manifest_is_source_bound_and_truthful() -> None:
    manifest = _manifest()
    normalized = validate_manifest(ROOT, manifest)
    report = audit_authority(
        ROOT,
        manifest,
        installed=True,
        version_probe=_matching_probe(manifest),
        artifact_probe=_matching_artifact_probe(manifest),
    )

    assert (
        artifact_digest(ROOT, normalized["shared_source_artifacts"])
        == normalized["shared_source_digest"]
    )
    assert report["shared_source_evidence_current"] is True
    assert all(host["source_evidence_current"] for host in report["hosts"])
    assert report["all_hosts_singular_authority"] is False
    assert report["current_boundaries"] == []
    assert report["blocked_hosts"] == ["mercury"]
    assert set(report["not_current_hosts"]) == PENDING_HOSTS | {"grok-build"}
    statuses = {host["id"]: host["authority_status"] for host in report["hosts"]}
    for host_id in PENDING_HOSTS:
        assert statuses[host_id] == "runtime_release_stale"
    assert statuses["grok-build"] == "repository_only"
    assert statuses["mercury"] == "blocked"


def test_authority_report_never_promotes_presence_or_a_new_version() -> None:
    manifest = _manifest()

    def probe(host_id: str) -> dict[str, object]:
        if host_id == "codex":
            return {"status": "present", "version": "999.0.0"}
        return {"status": "missing", "version": None}

    report = audit_authority(
        ROOT,
        manifest,
        installed=True,
        version_probe=probe,
        artifact_probe=_matching_artifact_probe(manifest),
    )
    statuses = {host["id"]: host["authority_status"] for host in report["hosts"]}

    for host_id in PENDING_HOSTS:
        assert statuses[host_id] == "runtime_release_stale"
    assert statuses["grok-build"] == "repository_only"
    assert statuses["mercury"] == "blocked"


def test_aip_artifact_receipt_must_match_the_reviewed_wheel() -> None:
    manifest = _manifest()
    binding = next(
        host["artifact_binding"] for host in manifest["hosts"] if host["id"] == "aip"
    )
    matching = _matching_artifact_probe(manifest)("aip")

    verified = verify_artifact_receipt(binding, matching)
    mismatched = dict(matching)
    mismatched["receipt"] = dict(matching["receipt"], artifact_sha256="f" * 64)

    assert verified["verified"] is True
    assert verified["artifact_sha256"] == binding["sha256"]
    assert verify_artifact_receipt(binding, mismatched) == {
        "status": "receipt_mismatch",
        "verified": False,
    }


def test_aip_artifact_mismatch_prevents_current_authority(
    qualified_fixture: tuple[Path, dict[str, Any]],
) -> None:
    root, manifest = qualified_fixture
    matching = _matching_artifact_probe(manifest)

    def mismatching_probe(host_id: str) -> dict[str, object]:
        result = matching(host_id)
        if host_id != "aip":
            return result
        return {
            "status": "present",
            "receipt": dict(result["receipt"], artifact_sha256="f" * 64),
        }

    report = audit_authority(
        root,
        manifest,
        installed=True,
        version_probe=_matching_probe(manifest),
        artifact_probe=mismatching_probe,
    )
    aip = next(host for host in report["hosts"] if host["id"] == "aip")

    assert aip["authority_status"] == "runtime_artifact_unverified"
    assert aip["artifact_probe"] == {
        "status": "receipt_mismatch",
        "verified": False,
    }
    assert "aip" in report["not_current_hosts"]


@pytest.mark.parametrize("state", ["qualified", "conditional"])
def test_current_fixture_requires_source_version_and_artifact_evidence(
    qualified_fixture: tuple[Path, dict[str, Any]], state: str
) -> None:
    root, manifest = qualified_fixture
    manifest["hosts"][0]["evidence_state"] = state

    report = audit_authority(
        root,
        manifest,
        installed=True,
        version_probe=_matching_probe(manifest),
        artifact_probe=_matching_artifact_probe(manifest),
    )

    assert report["hosts"][0]["authority_status"] == f"{state}_boundary_current"
    assert report["current_boundaries"] == ["aip"]


@pytest.mark.parametrize(
    ("runtime", "expected"),
    [
        ({"status": "present", "version": "999.0.0"}, "runtime_version_stale"),
        ({"status": "missing", "version": None}, "runtime_unavailable"),
        ({"status": "unrecognized", "version": None}, "runtime_unavailable"),
    ],
)
def test_qualified_fixture_rejects_unreviewed_runtime(
    qualified_fixture: tuple[Path, dict[str, Any]],
    runtime: dict[str, object],
    expected: str,
) -> None:
    root, manifest = qualified_fixture

    report = audit_authority(
        root,
        manifest,
        installed=True,
        version_probe=lambda _host: runtime,
        artifact_probe=_matching_artifact_probe(manifest),
    )

    assert report["hosts"][0]["authority_status"] == expected
    assert report["current_boundaries"] == []


@pytest.mark.parametrize("state", ["qualified", "release_pending"])
@pytest.mark.parametrize("source", ["shared.txt", "adapter.txt"])
def test_source_drift_still_blocks_qualified_and_pending_evidence(
    qualified_fixture: tuple[Path, dict[str, Any]], state: str, source: str
) -> None:
    root, manifest = qualified_fixture
    manifest["hosts"][0]["evidence_state"] = state
    (root / source).write_text("unreviewed change\n", encoding="utf-8")

    report = audit_authority(
        root,
        manifest,
        installed=True,
        version_probe=_matching_probe(manifest),
        artifact_probe=_matching_artifact_probe(manifest),
    )

    assert report["hosts"][0]["authority_status"] == "source_evidence_stale"
    assert report["hosts"][0]["source_evidence_current"] is False
    assert report["current_boundaries"] == []


@pytest.mark.parametrize("state", ["release_pending", "repository_only", "blocked"])
def test_require_current_rejects_unqualified_evidence_with_matching_artifacts(
    qualified_fixture: tuple[Path, dict[str, Any]],
    state: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, manifest = qualified_fixture
    manifest["hosts"][0]["evidence_state"] = state
    manifest_path = root / "authority.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(verify_host_authority, "ROOT", root)

    def matching_audit(root, manifest, *, installed=False):
        return audit_authority(
            root,
            manifest,
            installed=installed,
            version_probe=_matching_probe(manifest),
            artifact_probe=_matching_artifact_probe(manifest),
        )

    monkeypatch.setattr(verify_host_authority, "audit_authority", matching_audit)

    # Repository freshness is not an installed-host promotion gate.
    assert verify_host_authority.main(["--manifest", str(manifest_path)]) == 0
    assert json.loads(capsys.readouterr().out)["current_boundaries"] == []
    result = verify_host_authority.main(
        ["--manifest", str(manifest_path), "--require-current", "aip"]
    )
    report = json.loads(capsys.readouterr().out)

    assert result == 2
    assert report["shared_source_evidence_current"] is True
    assert report["current_boundaries"] == []
    expected = "runtime_release_stale" if state == "release_pending" else state
    assert report["gate_failures"] == [f"aip: {expected}"]


def test_authority_report_marks_changed_source_stale(tmp_path: Path) -> None:
    source = tmp_path / "gate.txt"
    source.write_text("reviewed gate\n", encoding="utf-8")
    digest = artifact_digest(tmp_path, ["gate.txt"])
    manifest = {
        "schema_version": 1,
        "profile": "profile",
        "scope": "scope",
        "shared_source_artifacts": ["gate.txt"],
        "shared_source_digest": digest,
        "hosts": [
            {
                "id": "codex",
                "display_name": "Codex",
                "adapter": "test",
                "evidence_state": "qualified",
                "qualified_boundary": "test root turns",
                "tested_on": "2026-07-25",
                "tested_version": "0.144.5",
                "source_artifacts": ["gate.txt"],
                "source_digest": digest,
                "checks": ["reviewed"],
                "remaining": ["none"],
            }
        ],
        "limitations": ["test only"],
    }
    source.write_text("changed gate\n", encoding="utf-8")

    report = audit_authority(
        tmp_path,
        manifest,
        installed=True,
        version_probe=lambda _host: {
            "status": "present",
            "version": "0.144.5",
        },
    )

    assert report["shared_source_evidence_current"] is False
    assert report["hosts"][0]["authority_status"] == "source_evidence_stale"


def test_authority_cli_fails_on_stale_source_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "gate.txt"
    source.write_text("reviewed gate\n", encoding="utf-8")
    digest = artifact_digest(tmp_path, ["gate.txt"])
    manifest = {
        "schema_version": 1,
        "profile": "profile",
        "scope": "scope",
        "shared_source_artifacts": ["gate.txt"],
        "shared_source_digest": digest,
        "hosts": [
            {
                "id": "codex",
                "display_name": "Codex",
                "adapter": "test",
                "evidence_state": "qualified",
                "qualified_boundary": "test root turns",
                "tested_on": "2026-07-25",
                "tested_version": "0.144.5",
                "source_artifacts": ["gate.txt"],
                "source_digest": digest,
                "checks": ["reviewed"],
                "remaining": ["none"],
            }
        ],
        "limitations": ["test only"],
    }
    manifest_path = tmp_path / "authority.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    source.write_text("changed gate\n", encoding="utf-8")
    monkeypatch.setattr(verify_host_authority, "ROOT", tmp_path)

    result = verify_host_authority.main(["--manifest", str(manifest_path)])
    report = json.loads(capsys.readouterr().out)

    assert result == 2
    assert report["source_evidence_failures"] == ["codex"]
    assert report["gate_failures"] == ["codex: source_evidence_stale"]


def test_authority_manifest_rejects_traversal_and_duplicate_keys(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authority.json"
    path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(ManifestError, match="duplicate JSON key"):
        load_manifest(path)

    manifest = _manifest()
    manifest["shared_source_artifacts"] = ["../outside"]
    with pytest.raises(ManifestError, match="unsafe artifact path"):
        audit_authority(ROOT, manifest)


def test_authority_manifest_contains_no_local_paths_or_payloads() -> None:
    text = DEFAULT_MANIFEST.read_text(encoding="utf-8")
    document = json.loads(text)

    assert "/Users/" not in text
    assert "scottwhitlock" not in text.casefold()
    assert "payload" not in document
    assert [host["id"] for host in document["hosts"]] == [
        "algo-cli",
        "aip",
        "openclaw",
        "hermes",
        "codex",
        "claude-code",
        "pi",
        "opencode",
        "droid",
        "goose",
        "grok-build",
        "mercury",
    ]
