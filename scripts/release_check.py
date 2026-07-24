#!/usr/bin/env python3
"""Validate release metadata and inspect built archives for unsafe contents."""

from __future__ import annotations

import argparse
import ast
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
    if tag is not None and tag != f"v{version}":
        errors.append(f"release tag {tag!r} must equal v{version}")

    versioned_json = (
        ".codex-plugin/plugin.json",
        "integrations/claude-code/.claude-plugin/plugin.json",
        "integrations/openclaw/openclaw.plugin.json",
        "integrations/openclaw/package.json",
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
        ".mcp.json",
        "integrations/README.md",
        "integrations/openclaw/package.json",
        "integrations/openclaw/openclaw.plugin.json",
        "integrations/openclaw/package-lock.json",
        "integrations/openclaw/dist/index.d.ts",
        "integrations/openclaw/dist/index.js",
        "integrations/claude-code/.claude-plugin/plugin.json",
        "integrations/claude-code/.mcp.json",
        "integrations/droid/.factory/mcp.json",
        "integrations/goose/echo-veil.yaml",
        "integrations/hermes/config.yaml",
        "integrations/mercury/SKILL.md",
        "integrations/opencode/opencode.json",
        "integrations/pi/package.json",
        "integrations/pi/package-lock.json",
        "integrations/pi/README.md",
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
            for member in archive.getmembers():
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
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--tag")
    parser.add_argument("--dist", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    version, errors = check_metadata(root, args.tag)
    if args.dist is not None:
        errors.extend(check_archives(args.dist.resolve(), version))
    if errors:
        print("Release validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"Release validation passed for {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
