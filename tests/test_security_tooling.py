from __future__ import annotations

from pathlib import Path

from scripts.privacy_scan import scan_text
from scripts.release_check import _unsafe_member, check_metadata
from scripts.security_scan import scan_python, scan_workflow


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

    version, errors = check_metadata(root, "v0.4.0")

    assert version == "0.4.0"
    assert errors == []


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
