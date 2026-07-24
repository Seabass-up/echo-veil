#!/usr/bin/env python3
"""Deterministic repository security policy checks.

This scanner is intentionally small and reviewable. It blocks dangerous
execution and deserialization primitives, mutable GitHub Action references,
and common supply-chain bypasses. It complements CodeQL and Trivy; it is not a
general-purpose malware detector.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ACTION_SHA = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$"
)
DOCKER_SHA = re.compile(r"^docker://[^\s@]+@sha256:[0-9a-f]{64}$")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
FROM = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE | re.MULTILINE)

BLOCKED_CALLS = {
    "eval": "dynamic code execution",
    "exec": "dynamic code execution",
    "compile": "dynamic code compilation",
    "__import__": "dynamic module loading",
    "builtins.eval": "dynamic code execution",
    "builtins.exec": "dynamic code execution",
    "builtins.compile": "dynamic code compilation",
    "builtins.__import__": "dynamic module loading",
    "os.system": "shell command execution",
    "os.popen": "shell command execution",
    "pickle.load": "unsafe deserialization",
    "pickle.loads": "unsafe deserialization",
    "marshal.load": "unsafe deserialization",
    "marshal.loads": "unsafe deserialization",
    "yaml.load": "unsafe YAML deserialization",
    "importlib.import_module": "dynamic module loading",
    "ssl._create_unverified_context": "TLS verification bypass",
    "tempfile.mktemp": "insecure temporary file creation",
    "ctypes.CDLL": "dynamic native library loading",
    "ctypes.PyDLL": "dynamic native library loading",
}

SUBPROCESS_CALLS = {
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
}

JS_BLOCKED = (
    (re.compile(r"\beval\s*\("), "dynamic JavaScript execution"),
    (re.compile(r"\bnew\s+Function\s*\("), "dynamic JavaScript compilation"),
    (re.compile(r"\b(?:innerHTML|outerHTML)\s*="), "unsafe HTML injection sink"),
    (re.compile(r"\bdangerouslySetInnerHTML\b"), "unsafe HTML injection sink"),
    (re.compile(r"\bchild_process\.(?:exec|execSync)\s*\("), "shell command execution"),
    (
        re.compile(
            r"\bimport\s*\{[^}]*\bexec(?:Sync)?\b[^}]*\}\s*from\s*"
            r"[\"'](?:node:)?child_process[\"']"
        ),
        "shell command execution import",
    ),
    (
        re.compile(
            r"\b(?:const|let|var)\s*\{[^}]*\bexec(?:Sync)?\b[^}]*\}\s*=\s*"
            r"require\s*\(\s*[\"'](?:node:)?child_process[\"']\s*\)"
        ),
        "shell command execution import",
    ),
    (re.compile(r"\bshell\s*:\s*true\b"), "subprocess shell enabled"),
    (
        re.compile(r"\.\.\.\s*process\.env\b"),
        "unfiltered host environment inheritance",
    ),
    (
        re.compile(r"\.startsWith\(\s*[\"']ECHO_VEIL_[\"']\s*\)"),
        "blanket Echo Veil environment inheritance",
    ),
)

SHELL_PIPE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
    re.IGNORECASE,
)

PROHIBITED_BINARY_SUFFIXES = {
    ".dll",
    ".dylib",
    ".exe",
    ".pkl",
    ".pickle",
    ".so",
}

SKIP_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "target",
}


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


def _call_name(node: ast.Call, aliases: dict[str, str]) -> str:
    current: ast.expr = node.func
    parts: list[str] = []
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        root = aliases.get(current.id, current.id)
        return ".".join([root, *reversed(parts)])
    return ""


def scan_python(path: Path, display: str) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=display)
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        line = getattr(exc, "lineno", 1) or 1
        return [Finding(display, line, f"cannot safely parse Python: {exc}")]

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                aliases[imported.asname or imported.name] = imported.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for imported in node.names:
                aliases[imported.asname or imported.name] = (
                    f"{node.module}.{imported.name}"
                )

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node, aliases)
        reason = BLOCKED_CALLS.get(call_name)
        if reason:
            findings.append(
                Finding(display, node.lineno, f"blocked {reason}: {call_name}()")
            )
        if call_name in SUBPROCESS_CALLS:
            for keyword in node.keywords:
                if keyword.arg != "shell":
                    continue
                if not (
                    isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ):
                    findings.append(
                        Finding(
                            display,
                            node.lineno,
                            "subprocess shell must be the literal False or omitted",
                        )
                    )
        for keyword in node.keywords:
            if keyword.arg == "verify" and isinstance(keyword.value, ast.Constant):
                if keyword.value.value is False:
                    findings.append(
                        Finding(
                            display,
                            node.lineno,
                            "TLS certificate verification disabled",
                        )
                    )
    return findings


def scan_javascript(path: Path, display: str) -> list[Finding]:
    text = path.read_text(encoding="utf-8")
    findings: list[Finding] = []
    for pattern, message in JS_BLOCKED:
        for match in pattern.finditer(text):
            findings.append(
                Finding(display, text.count("\n", 0, match.start()) + 1, message)
            )
    shell_match = SHELL_PIPE.search(text)
    if shell_match is not None:
        findings.append(
            Finding(
                display,
                text.count("\n", 0, shell_match.start()) + 1,
                "remote content piped directly to a shell",
            )
        )
    return findings


def scan_workflow(path: Path, display: str) -> list[Finding]:
    text = path.read_text(encoding="utf-8")
    findings: list[Finding] = []
    if not re.search(r"^permissions:\s*(?:\n|\{)", text, re.MULTILINE):
        findings.append(
            Finding(display, 1, "workflow needs explicit top-level permissions")
        )
    if re.search(r"^\s*pull_request_target\s*:", text, re.MULTILINE):
        findings.append(Finding(display, 1, "pull_request_target is prohibited"))
    if re.search(r"runs-on:\s*.*self-hosted", text):
        findings.append(Finding(display, 1, "self-hosted runners are prohibited"))
    if re.search(r"continue-on-error:\s*true", text, re.IGNORECASE):
        findings.append(Finding(display, 1, "continue-on-error may not bypass a gate"))
    if re.search(r"run:\s*[^\n]*\$\{\{\s*github\.event\.", text):
        findings.append(
            Finding(
                display, 1, "untrusted event data interpolated directly into a shell"
            )
        )
    for match in USES.finditer(text):
        reference = match.group(1).strip("'\"")
        if reference.startswith("./"):
            continue
        if not (ACTION_SHA.fullmatch(reference) or DOCKER_SHA.fullmatch(reference)):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    display,
                    line,
                    f"action is not pinned to an immutable SHA: {reference}",
                )
            )
    return findings


def scan_dockerfile(path: Path, display: str) -> list[Finding]:
    text = path.read_text(encoding="utf-8")
    findings: list[Finding] = []
    for match in FROM.finditer(text):
        image = match.group(1)
        if image.lower() != "scratch" and not re.search(
            r"@sha256:[0-9a-f]{64}$", image
        ):
            findings.append(
                Finding(
                    display,
                    text.count("\n", 0, match.start()) + 1,
                    f"base image is not digest-pinned: {image}",
                )
            )
    if re.search(r"^\s*ADD\s+https?://", text, re.IGNORECASE | re.MULTILINE):
        findings.append(Finding(display, 1, "remote Docker ADD is prohibited"))
    if SHELL_PIPE.search(text):
        findings.append(Finding(display, 1, "remote content piped directly to a shell"))
    if not re.search(r"^\s*USER\s+(?!0\b|root\b)", text, re.IGNORECASE | re.MULTILINE):
        findings.append(
            Finding(display, 1, "runtime image must declare a non-root USER")
        )
    return findings


def _candidate_files(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        tracked_openclaw_dist = relative.parts[:3] == (
            "integrations",
            "openclaw",
            "dist",
        )
        skipped_parts = SKIP_PARTS - {"dist"} if tracked_openclaw_dist else SKIP_PARTS
        if any(part in skipped_parts for part in relative.parts):
            continue
        if relative.parts[0] not in {
            ".github",
            "cloudflare",
            "crates",
            "deploy",
            "examples",
            "integrations",
            "scripts",
            "src",
            "tests",
            "website",
        }:
            continue
        candidates.append(path)
    return sorted(candidates)


def scan_repository(root: Path) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for path in _candidate_files(root):
        display = path.relative_to(root).as_posix()
        if path.suffix.lower() in PROHIBITED_BINARY_SUFFIXES:
            findings.append(
                Finding(display, 1, "binary payload is prohibited in source")
            )
            continue
        try:
            if path.suffix == ".py":
                findings.extend(scan_python(path, display))
            elif path.suffix in {".js", ".mjs", ".ts", ".tsx"}:
                findings.extend(scan_javascript(path, display))
            elif path.parent.name == "workflows" and path.suffix in {".yml", ".yaml"}:
                findings.extend(scan_workflow(path, display))
            elif path.name.lower() == "dockerfile":
                findings.extend(scan_dockerfile(path, display))
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(Finding(display, 1, f"cannot safely inspect file: {exc}"))
    return sorted(set(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    args = parser.parse_args(argv)
    findings = scan_repository(args.root)
    if findings:
        print("Security policy violations:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding.render()}", file=sys.stderr)
        return 1
    print("Security policy scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
