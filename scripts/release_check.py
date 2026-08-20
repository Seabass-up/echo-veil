#!/usr/bin/env python3
"""Validate release metadata and inspect built archives for unsafe contents."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import tarfile

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10
    import tomli as tomllib
import zipfile
from pathlib import Path, PurePosixPath


VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[a-z]+[0-9]+)?$")
PROHIBITED_PARTS = {".env", ".git", ".github", "AGENTS.md", "node_modules"}
PROHIBITED_SUFFIXES = {
    ".db",
    ".der",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".tfplan",
    ".tfstate",
}
REQUIRED_SDIST_FILES = {
    "compatibility/probes/openclaw-v0.7.0.test.ts",
    "compatibility/probes/opencode-v0.7.0.test.mjs",
    "compatibility/probes/pi-v0.7.0.test.ts",
    "compatibility/probes/python-v0.7.0.py",
    ".agents/plugins/marketplace.json",
    ".claude-plugin/marketplace.json",
    ".factory-plugin/marketplace.json",
    "hooks/hooks.json",
    "integrations/aip/README.md",
    "integrations/algo-cli/README.md",
    "integrations/authority-evidence.json",
    "integrations/claude-code/skills/echo-veil-memory/SKILL.md",
    "integrations/claude-code/hooks/hooks.json",
    "integrations/hermes/README.md",
    "integrations/hermes/plugin/__init__.py",
    "integrations/hermes/plugin/plugin.yaml",
    "integrations/hermes/skills/echo-veil-memory/SKILL.md",
    "integrations/droid/.factory/skills/echo-veil-memory/SKILL.md",
    "integrations/droid/.factory-plugin/plugin.json",
    "integrations/droid/.factory/hooks.json",
    "integrations/droid/.factory/hooks/echo-veil-preflight.sh",
    "integrations/droid/hooks/hooks.json",
    "integrations/droid/hooks/echo-veil-preflight.sh",
    "integrations/droid/mcp.json",
    "integrations/droid/README.md",
    "integrations/droid/skills/echo-veil-memory/SKILL.md",
    "integrations/goose/echo-veil.yaml",
    "integrations/goose/README.md",
    "integrations/mercury/SKILL.md",
    "integrations/opencode/.opencode/plugins/echo-veil-shield.js",
    "integrations/opencode/.opencode/skills/echo-veil-memory/SKILL.md",
    "integrations/opencode/README.md",
    "integrations/opencode/package.json",
    "integrations/opencode/package-lock.json",
    "integrations/opencode/tests/echo-veil-shield.test.mjs",
    "integrations/pi/extensions/index.ts",
    "integrations/pi/artifact-receipt.json",
    "integrations/pi/src/artifact.ts",
    "integrations/pi/src/preflight.ts",
    "integrations/pi/src/runner.ts",
    "integrations/pi/skills/echo-veil-memory/SKILL.md",
    "protocol/README.md",
    "protocol/fixtures/compatibility-v1.json",
    "protocol/n-minus-one-v0.7.0.json",
    "protocol/registry-v1.json",
    "scripts/memory_core_benchmark.py",
    "scripts/build_openclaw_archive.py",
    "scripts/migrate_agent_profile.py",
    "scripts/migrate_host_memory.py",
    "scripts/verify_agent_profile_migration.py",
    "scripts/verify_host_authority.py",
    "scripts/verify_n_minus_one_consumers.py",
    "scripts/privacy_scan.py",
    "scripts/quality_benchmark.py",
    "scripts/release_check.py",
    "scripts/secure_bundle.py",
    "scripts/security_scan.py",
    "src/echo_veil/guarded_runner.py",
    "src/echo_veil/agent_broker.py",
    "src/echo_veil/backup.py",
    "src/echo_veil/codex_artifact.py",
    "src/echo_veil/local_authority.py",
    "src/echo_veil/readiness_store.py",
    "src/echo_veil/preflight_receipt.py",
    "src/echo_veil/protocol_compat.py",
    "skills/echo-veil-memory/SKILL.md",
    "skills/echo-veil-memory/agents/openai.yaml",
}


def _module_version(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str
            ):
                return node.value.value
    raise ValueError(f"{path} does not declare a literal __version__")


def check_metadata(root: Path, tag: str | None = None) -> tuple[str, list[str]]:
    errors: list[str] = []
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata["project"]
    version = project["version"]
    module_version = _module_version(root / "src/echo_veil/__init__.py")
    if not VERSION.fullmatch(version):
        errors.append(f"project version is not release-shaped: {version}")
    if module_version != version:
        errors.append(f"module version {module_version} != project version {version}")
    if project.get("license") != "MIT":
        errors.append("project license metadata must be MIT")
    scripts = project.get("scripts", {})
    expected_scripts = {
        "echo-veil-agent": "echo_veil.agent_cli:main",
        "echo-veil-preflight-hook": "echo_veil.agent_preflight:main",
        "echo-veil-shielded-run": "echo_veil.guarded_runner:main",
    }
    if scripts != expected_scripts:
        errors.append("project script entry points do not match the protected CLI set")
    if tag is not None and tag != f"v{version}":
        errors.append(f"release tag {tag!r} must equal v{version}")

    versioned_json = (
        ".codex-plugin/plugin.json",
        "integrations/claude-code/.claude-plugin/plugin.json",
        "integrations/droid/.factory-plugin/plugin.json",
        "integrations/openclaw/openclaw.plugin.json",
        "integrations/openclaw/package.json",
        "integrations/opencode/package.json",
        "integrations/pi/package.json",
    )
    for name in versioned_json:
        path = root / name
        if not path.is_file():
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("version") != version:
            errors.append(
                f"{name} version {document.get('version')} != project version {version}"
            )
    deployment_lock = root / "integrations/openclaw/deployment-lock.json"
    if deployment_lock.is_file():
        lock = json.loads(deployment_lock.read_text(encoding="utf-8"))
        epoch = lock.get("source_date_epoch")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
            errors.append(
                "integrations/openclaw/deployment-lock.json source_date_epoch "
                "must be a positive integer"
            )
        for label in ("plugin", "python"):
            item = lock.get(label)
            if not isinstance(item, dict) or item.get("version") != version:
                errors.append(
                    "integrations/openclaw/deployment-lock.json "
                    f"{label} version does not equal {version}"
                )
    hermes_manifest = root / "integrations/hermes/plugin/plugin.yaml"
    if hermes_manifest.is_file():
        manifest_text = hermes_manifest.read_text(encoding="utf-8")
        if f'version: "{version}"' not in manifest_text:
            errors.append(
                "integrations/hermes/plugin/plugin.yaml version "
                f"does not equal {version}"
            )
    mercury_skill = root / "integrations/mercury/SKILL.md"
    if mercury_skill.is_file():
        skill_text = mercury_skill.read_text(encoding="utf-8")
        if f"version: {version}" not in skill_text:
            errors.append(
                f"integrations/mercury/SKILL.md version does not equal {version}"
            )
    claude_marketplace = root / ".claude-plugin/marketplace.json"
    if claude_marketplace.is_file():
        document = json.loads(claude_marketplace.read_text(encoding="utf-8"))
        plugins = document.get("plugins")
        if not isinstance(plugins, list) or len(plugins) != 1:
            errors.append(".claude-plugin/marketplace.json must declare one plugin")
        elif not isinstance(plugins[0], dict):
            errors.append(".claude-plugin/marketplace.json plugin must be an object")
        elif plugins[0].get("version") != version:
            errors.append(
                ".claude-plugin/marketplace.json plugin version "
                f"{plugins[0].get('version')} != project version {version}"
            )

    required = (
        "CHANGELOG.md",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "docs/LOCAL_AGENT_SECURITY.md",
        "uv.lock",
        ".dockerignore",
        "crates/echo-veil-zkp/Cargo.toml",
        "crates/echo-veil-zkp/Cargo.lock",
        "cloudflare/enclave-gateway/package.json",
        "cloudflare/enclave-gateway/package-lock.json",
        "deploy/enclave/Dockerfile",
        ".codex-plugin/plugin.json",
        ".agents/plugins/marketplace.json",
        ".claude-plugin/marketplace.json",
        ".factory-plugin/marketplace.json",
        ".mcp.json",
        "integrations/README.md",
        "integrations/aip/README.md",
        "integrations/algo-cli/README.md",
        "integrations/authority-evidence.json",
        "scripts/build_openclaw_archive.py",
        "scripts/migrate_agent_profile.py",
        "scripts/migrate_host_memory.py",
        "scripts/verify_agent_profile_migration.py",
        "scripts/verify_host_authority.py",
        "scripts/verify_openclaw_deployment.py",
        "scripts/migrate_hashing_profile.py",
        "integrations/openclaw/deployment-lock.json",
        "integrations/openclaw/package.json",
        "integrations/openclaw/openclaw.plugin.json",
        "integrations/openclaw/package-lock.json",
        "integrations/openclaw/dist/index.d.ts",
        "integrations/openclaw/dist/index.js",
        "integrations/claude-code/.claude-plugin/plugin.json",
        "integrations/claude-code/.mcp.json",
        "integrations/claude-code/skills/echo-veil-memory/SKILL.md",
        "integrations/claude-code/hooks/hooks.json",
        "hooks/hooks.json",
        "integrations/droid/.factory/mcp.json",
        "integrations/droid/.factory/hooks.json",
        "integrations/droid/.factory/hooks/echo-veil-preflight.sh",
        "integrations/droid/.factory/skills/echo-veil-memory/SKILL.md",
        "integrations/droid/.factory-plugin/plugin.json",
        "integrations/droid/hooks/hooks.json",
        "integrations/droid/hooks/echo-veil-preflight.sh",
        "integrations/droid/mcp.json",
        "integrations/droid/README.md",
        "integrations/droid/skills/echo-veil-memory/SKILL.md",
        "integrations/goose/echo-veil.yaml",
        "integrations/goose/README.md",
        "integrations/hermes/README.md",
        "integrations/hermes/config.yaml",
        "integrations/hermes/plugin/__init__.py",
        "integrations/hermes/plugin/plugin.yaml",
        "integrations/hermes/skills/echo-veil-memory/SKILL.md",
        "integrations/mercury/SKILL.md",
        "integrations/opencode/opencode.json",
        "integrations/opencode/package.json",
        "integrations/opencode/package-lock.json",
        "integrations/opencode/README.md",
        "integrations/opencode/.opencode/plugins/echo-veil-shield.js",
        "integrations/opencode/.opencode/skills/echo-veil-memory/SKILL.md",
        "integrations/opencode/tests/echo-veil-shield.test.mjs",
        "integrations/pi/package.json",
        "integrations/pi/package-lock.json",
        "integrations/pi/README.md",
        "integrations/pi/extensions/index.ts",
        "integrations/pi/src/preflight.ts",
        "integrations/pi/skills/echo-veil-memory/SKILL.md",
        "skills/echo-veil-memory/SKILL.md",
        "skills/echo-veil-memory/agents/openai.yaml",
        "src/echo_veil/guarded_runner.py",
        "website/package.json",
        "website/package-lock.json",
        "website/wrangler.production.jsonc",
        "deploy/cloudflare/.terraform.lock.hcl",
    )
    for name in required:
        if not (root / name).is_file():
            errors.append(f"required release file is missing: {name}")
    changelog = root / "CHANGELOG.md"
    if changelog.is_file() and f"## [{version}]" not in changelog.read_text(
        encoding="utf-8"
    ):
        errors.append(f"CHANGELOG.md has no [{version}] release section")

    policy_requirements = {
        "hooks/hooks.json": (
            "UserPromptSubmit",
            "echo-veil-preflight-hook",
            "--host codex",
        ),
        "integrations/claude-code/hooks/hooks.json": (
            "UserPromptSubmit",
            "UserPromptExpansion",
            "echo-veil-preflight-hook",
            "--host claude-code",
        ),
        "src/echo_veil/agent_preflight.py": (
            "top_k=2",
            "allow_inferential=False",
            "untrusted_memory_evidence",
            "ranking_ambiguous",
            "competing_memory_detected",
            "REQUIRED_PREFLIGHT_FAILURE",
        ),
        "integrations/pi/extensions/index.ts": (
            'pi.on("input"',
            'pi.on("before_agent_start"',
            'pi.on("agent_start"',
            'pi.on("tool_call"',
            "ctx.abort()",
            "REQUIRED_PREFLIGHT_FAILURE",
        ),
        "integrations/pi/src/preflight.ts": (
            'this.rpc("preflight_v2"',
            "ritual_satisfied",
            "MAX_PREFLIGHT_ESTIMATED_TOKENS",
            "payload_included",
            "untrusted_memory_evidence",
            "ranking_ambiguous",
            "competing_memory_detected",
        ),
        "src/echo_veil/agent_broker.py": (
            "owner-only",
            "payload_included",
            "serve_forever",
        ),
        "integrations/droid/hooks/hooks.json": (
            "UserPromptSubmit",
            "PreToolUse",
            "Task",
            "echo-veil-preflight.sh",
        ),
        "integrations/droid/hooks/echo-veil-preflight.sh": (
            "ECHO_VEIL_PREFLIGHT_COMMAND",
            "--host droid",
            "--hook-mode",
            "exit 2",
        ),
        "integrations/mercury/SKILL.md": (
            "SECOND_BRAIN_ENABLED=false",
            "not an all-memory-off switch",
            "incompatible with singular-authority mode",
            "must not mutate Mercury's memory configuration",
            "readiness check",
        ),
        "integrations/goose/echo-veil.yaml": (
            "do not launch Goose with",
            "--no-profile",
            "echo_veil_doctor",
            "echo_veil_recall",
            "top_k 2",
            "inferential recall disabled",
        ),
        "src/echo_veil/guarded_runner.py": (
            "echo-veil-shielded-run",
            "--no-profile",
            "--no-session",
            "--disable-builtin-skills",
            '"Task"',
            "HERMES_PLUGIN_DIGESTS",
            "_isolated_hermes_environment",
            '"echo-veil-run"',
            "shell=False",
            "REQUIRED_PREFLIGHT_FAILURE",
        ),
        "integrations/opencode/.opencode/plugins/echo-veil-shield.js": (
            '"chat.message"',
            '"chat.params"',
            '"tool.execute.before"',
            '"experimental.compaction.autocontinue"',
            "subagent_task",
            "ECHO_VEIL_FORCE_PREFLIGHT_FAILURE",
            "REQUIRED_PREFLIGHT_FAILURE",
            "shell: false",
        ),
        "integrations/hermes/plugin/__init__.py": (
            'register_hook("pre_llm_call"',
            'register_middleware("llm_execution"',
            "ECHO_VEIL_FORCE_HERMES_PREFLIGHT_FAILURE",
            "ECHO_VEIL_HERMES_TURN_NONCE",
            "register_cli_command",
            "SHIELDED_RUN_NONCE_ENV",
            'toolsets="echo-veil"',
            "REQUIRED_PREFLIGHT_FAILURE",
            "shell=False",
            "MAX_CONTEXT_CHARS = 9_000",
        ),
    }
    for name, phrases in policy_requirements.items():
        path = root / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for phrase in phrases:
            if phrase not in text:
                errors.append(f"{name} is missing required policy text: {phrase}")
    return version, errors


def _unsafe_member(name: str) -> str | None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        return "archive path traversal"
    if any(part in PROHIBITED_PARTS for part in path.parts):
        return "prohibited private or repository-control file"
    if path.suffix.lower() in PROHIBITED_SUFFIXES:
        return "secret or runtime-state file"
    return None


def check_archives(dist: Path, version: str) -> list[str]:
    errors: list[str] = []
    wheels = sorted(dist.glob("echo_veil-*.whl"))
    sdists = sorted(dist.glob("echo_veil-*.tar.gz"))
    if len(wheels) != 1:
        errors.append(f"expected one wheel, found {len(wheels)}")
    if len(sdists) != 1:
        errors.append(f"expected one sdist, found {len(sdists)}")

    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            for name in names:
                reason = _unsafe_member(name)
                if reason:
                    errors.append(f"{wheel.name}: {reason}: {name}")
            metadata_name = f"echo_veil-{version}.dist-info/METADATA"
            if metadata_name not in names:
                errors.append(f"{wheel.name}: missing {metadata_name}")
            else:
                metadata = archive.read(metadata_name).decode("utf-8")
                if f"Version: {version}" not in metadata:
                    errors.append(f"{wheel.name}: embedded version is incorrect")
                if "License-Expression: MIT" not in metadata:
                    errors.append(f"{wheel.name}: missing MIT license expression")

    for sdist in sdists:
        root_name = f"echo_veil-{version}"
        prefix = f"echo_veil-{version}/"
        with tarfile.open(sdist, "r:gz") as archive:
            members = archive.getmembers()
            member_names = {member.name for member in members}
            for member in members:
                if member.issym() or member.islnk():
                    errors.append(
                        f"{sdist.name}: archive link is prohibited: {member.name}"
                    )
                if member.name != root_name and not member.name.startswith(prefix):
                    errors.append(
                        f"{sdist.name}: unexpected archive root: {member.name}"
                    )
                reason = _unsafe_member(member.name)
                if reason:
                    errors.append(f"{sdist.name}: {reason}: {member.name}")
            for required in sorted(REQUIRED_SDIST_FILES):
                expected = f"{root_name}/{required}"
                if expected not in member_names:
                    errors.append(f"{sdist.name}: missing required file: {required}")
    return errors


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_locked_artifacts(
    root: Path,
    *,
    dist: Path | None = None,
    plugin_archive: Path | None = None,
) -> list[str]:
    """Bind locally built artifacts to the reviewed deployment lock."""

    errors: list[str] = []
    lock_path = root / "integrations/openclaw/deployment-lock.json"
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        plugin = lock["plugin"]
        python = lock["python"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        return [f"deployment lock cannot bind release artifacts: {exc}"]

    entrypoint = root / "integrations/openclaw/dist/index.js"
    if not entrypoint.is_file():
        errors.append("OpenClaw entrypoint is missing")
    elif _sha256(entrypoint) != plugin.get("entrypoint_sha256"):
        errors.append("OpenClaw entrypoint does not match deployment lock")

    if dist is not None:
        wheels = sorted(dist.glob("echo_veil-*.whl"))
        if len(wheels) == 1 and _sha256(wheels[0]) != python.get("wheel_sha256"):
            errors.append("Python wheel does not match deployment lock")

    if plugin_archive is not None:
        if not plugin_archive.is_file():
            errors.append("OpenClaw plugin archive is missing")
        elif _sha256(plugin_archive) != plugin.get("archive_sha256"):
            errors.append("OpenClaw plugin archive does not match deployment lock")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--tag")
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--plugin-archive", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    version, errors = check_metadata(root, args.tag)
    if args.dist is not None:
        errors.extend(check_archives(args.dist.resolve(), version))
    errors.extend(
        check_locked_artifacts(
            root,
            dist=args.dist.resolve() if args.dist is not None else None,
            plugin_archive=(
                args.plugin_archive.resolve()
                if args.plugin_archive is not None
                else None
            ),
        )
    )
    if errors:
        print("Release validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"Release validation passed for {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
