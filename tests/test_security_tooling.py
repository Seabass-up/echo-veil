from __future__ import annotations

from pathlib import Path

from scripts.privacy_scan import scan_repository as scan_privacy_repository
from scripts.privacy_scan import scan_text
from scripts.release_check import _unsafe_member, check_locked_artifacts, check_metadata
from scripts.security_scan import (
    _candidate_files,
    scan_javascript,
    scan_python,
    scan_workflow,
)


def test_security_scanner_rejects_dynamic_execution(tmp_path: Path) -> None:
    source = tmp_path / "bad.py"
    source.write_text("value = eval(user_input)\n", encoding="utf-8")

    findings = scan_python(source, "bad.py")

    assert any("dynamic code execution" in finding.message for finding in findings)


def test_security_scanner_rejects_shell_subprocess(tmp_path: Path) -> None:
    source = tmp_path / "bad.py"
    source.write_text(
        "import subprocess\nsubprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    findings = scan_python(source, "bad.py")

    assert any("shell must be" in finding.message for finding in findings)


def test_security_scanner_rejects_javascript_shell_and_environment_spread(
    tmp_path: Path,
) -> None:
    source = tmp_path / "bad.ts"
    source.write_text(
        'import { exec } from "node:child_process";\n'
        "spawn(command, [], { shell: true, env: { ...process.env } });\n",
        encoding="utf-8",
    )

    findings = scan_javascript(source, "bad.ts")

    assert any("shell command execution import" in item.message for item in findings)
    assert any("subprocess shell enabled" in item.message for item in findings)
    assert any("host environment inheritance" in item.message for item in findings)


def test_security_scanner_rejects_blanket_echo_environment_allowlist(
    tmp_path: Path,
) -> None:
    source = tmp_path / "bad.ts"
    source.write_text(
        'if (name.startsWith("ECHO_VEIL_")) child[name] = value;\n',
        encoding="utf-8",
    )

    findings = scan_javascript(source, "bad.ts")

    assert any("blanket Echo Veil" in item.message for item in findings)


def test_security_scanner_narrowly_allows_raw_html_lint_selector(
    tmp_path: Path,
) -> None:
    source = tmp_path / "eslint.config.mjs"
    source.write_text(
        """selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",\n""",
        encoding="utf-8",
    )

    allowed = scan_javascript(source, "website/eslint.config.mjs")
    wrong_path = scan_javascript(source, "other/eslint.config.mjs")
    source.write_text(
        "element.innerHTML = untrusted;\n"
        """selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",\n""",
        encoding="utf-8",
    )
    sink_in_same_file = scan_javascript(source, "website/eslint.config.mjs")

    assert allowed == []
    assert any("unsafe HTML injection" in item.message for item in wrong_path)
    assert [item.line for item in sink_in_same_file] == [1]


def test_repository_scanner_includes_distributed_openclaw_plugin() -> None:
    root = Path(__file__).resolve().parents[1]
    relative = {path.relative_to(root).as_posix() for path in _candidate_files(root)}

    assert "integrations/openclaw/dist/index.js" in relative
    assert "skills/echo-veil-memory/SKILL.md" in relative


def test_repository_scanners_prune_dependency_trees(tmp_path: Path) -> None:
    source = tmp_path / "src" / "safe.py"
    source.parent.mkdir()
    source.write_text("value = 1\n", encoding="utf-8")
    dependency = tmp_path / "integrations" / "sample" / "node_modules" / "bad.py"
    dependency.parent.mkdir(parents=True)
    dependency.write_text(
        "value = eval(user_input)\n"
        "path = '/Users/developer/private'\n",  # privacy-scan:allow -- fixture
        encoding="utf-8",
    )

    candidates = {
        path.relative_to(tmp_path).as_posix() for path in _candidate_files(tmp_path)
    }
    privacy_findings = scan_privacy_repository(tmp_path)

    assert candidates == {"src/safe.py"}
    assert privacy_findings == []


def test_workflow_scanner_requires_immutable_action_refs(tmp_path: Path) -> None:
    workflow = tmp_path / "bad.yml"
    workflow.write_text(
        "permissions:\n  contents: read\njobs:\n  test:\n"
        "    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )

    findings = scan_workflow(workflow, "bad.yml")

    assert any("immutable SHA" in finding.message for finding in findings)


def test_release_metadata_is_consistent() -> None:
    root = Path(__file__).resolve().parents[1]

    version, errors = check_metadata(root, "v0.8.0")
    manifest = (root / "MANIFEST.in").read_text(encoding="utf-8")

    assert version == "0.8.0"
    assert errors == []
    assert "recursive-include scripts *.py" in manifest
    assert "include integrations/algo-cli/README.md" in manifest
    assert "include integrations/openclaw/deployment-lock.json" in manifest
    assert "recursive-include skills *.md *.yaml" in manifest
    assert "recursive-include integrations/claude-code/skills *.md" in manifest
    assert "include hooks/hooks.json" in manifest
    assert "recursive-include integrations/claude-code/hooks *.json" in manifest
    assert "include .grok-plugin/marketplace.json" in manifest
    assert "recursive-include integrations/grok/hooks *.json" in manifest


def test_release_artifacts_are_bound_to_deployment_lock(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    archive = tmp_path / "openclaw-plugin-echo-veil-0.8.0.tgz"
    archive.write_bytes(b"not the reviewed archive")

    errors = check_locked_artifacts(root, plugin_archive=archive)

    assert errors == ["OpenClaw plugin archive does not match deployment lock"]


def test_enclave_image_context_is_allowlisted_and_nonroot_readable() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    dockerfile = (root / "deploy/enclave/Dockerfile").read_text(encoding="utf-8")

    assert dockerignore.startswith("**\n")
    assert "!src/echo_veil/*.py" in dockerignore
    assert "!src/echo_veil_origin/*.py" in dockerignore
    assert "!crates/echo-veil-zkp/src/*.rs" in dockerignore
    assert "COPY --chown=0:10001 src ./src" in dockerfile
    assert "find /app/src -type d -exec chmod 0550" in dockerfile
    assert "find /app/src -type f -exec chmod 0440" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert 'RUN python3 -c "import echo_veil, echo_veil_origin, openfhe"' in dockerfile

    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    compose = (root / "deploy/enclave/compose.yaml").read_text(encoding="utf-8")
    assert "platforms: linux/amd64" in workflow
    assert "platform: linux/amd64" in compose


def test_release_workflows_build_reproducible_openclaw_archives() -> None:
    root = Path(__file__).resolve().parents[1]
    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    release = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert 'scripts/build_openclaw_archive.py --epoch "$ARCHIVE_EPOCH"' in ci
    assert "--output-dir /tmp/echo-veil-openclaw-a" in ci
    assert "--output-dir /tmp/echo-veil-openclaw-b" in ci
    assert "scripts/build_openclaw_archive.py --output-dir release" in release


def test_ci_runs_the_full_local_qualification_gate() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    assert "local-qualification:" in workflow
    assert "scripts/qualification_benchmark.py" in workflow
    assert "--sizes 1000 10000 100000" in workflow
    assert "--dimension 1024" in workflow
    assert "--queries 12" in workflow


def test_release_requires_green_ci_for_the_exact_tagged_commit() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "actions: read" in workflow
    assert 'SOURCE_COMMIT="$(git rev-parse HEAD)"' in workflow
    assert '-f head_sha="$SOURCE_COMMIT"' in workflow
    assert "-f status=completed" in workflow
    assert '.conclusion == "success"' in workflow


def test_enclave_docs_keep_the_ckks_key_state_blocker_visible() -> None:
    root = Path(__file__).resolve().parents[1]
    for relative in (
        "README.md",
        "docs/DEPLOYMENT_RUNBOOK.md",
        "docs/DEPLOYMENT_THREAT_MODEL.md",
    ):
        text = (root / relative).read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        assert "externally pinned authenticated" in normalized
        assert "public-key-derived" in normalized or "actual public key" in normalized
        assert "key ID" in normalized
        assert "startup" in normalized
        assert "encrypt/evaluate/decrypt self-test" in normalized


def test_release_archive_policy_rejects_secrets_and_traversal() -> None:
    assert _unsafe_member("echo-veil/.env") is not None
    assert _unsafe_member("../secret.txt") is not None
    assert _unsafe_member("echo-veil/src/echo_veil/oracle.py") is None


def test_privacy_scanner_rejects_local_paths_and_personal_email() -> None:
    findings = scan_text(
        "cache=/Users/developer/project\ncontact=person@company.test\n",  # privacy-scan:allow -- detector fixture
        "sample.txt",
    )

    assert any("developer-machine path" in finding.message for finding in findings)
    assert any(
        "personal or non-placeholder email" in finding.message for finding in findings
    )


def test_privacy_scanner_allows_placeholders_and_github_noreply() -> None:
    findings = scan_text(
        "endpoint=memory.example.com\n"
        "author=123+user@users.noreply.github.com\n"
        "merge=noreply@github.com\n",
        "sample.txt",
    )

    assert findings == []


def test_privacy_scanner_ignores_generated_swift_build_metadata(
    tmp_path: Path,
) -> None:
    generated = tmp_path / "native" / "helper" / ".build" / "release"
    generated.mkdir(parents=True)
    (generated / "description.json").write_text(
        '{"source":"/Users/developer/project/main.swift"}',  # privacy-scan:allow -- ignored-build fixture
        encoding="utf-8",
    )

    assert scan_privacy_repository(tmp_path) == []
