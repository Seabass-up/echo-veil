#!/usr/bin/env python3
"""Reject developer-machine paths, personal email addresses, and unsafe Git identities."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


LOCAL_PATH = re.compile(
    r"(?:/Users/[^/\s]+/|/home/[^/\s]+/|[A-Za-z]:[\\/]Users[\\/][^\\/\s]+[\\/])"  # privacy-scan:allow -- detector definition
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
SAFE_EMAIL_SUFFIXES = (
    ".example.com",
    ".example.net",
    ".example.org",
    "@example.com",
    "@example.net",
    "@example.org",
    "@users.noreply.github.com",
)
SAFE_EMAILS = {"noreply@github.com"}
SKIP_PARTS = {
    ".build",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    ".venv",
    ".vinext",
    ".wrangler",
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


def _is_safe_email(value: str) -> bool:
    lower = value.lower()
    return lower in SAFE_EMAILS or any(
        lower.endswith(suffix) for suffix in SAFE_EMAIL_SUFFIXES
    )


def scan_text(text: str, display: str) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if "privacy-scan:allow" in line:
            continue
        if LOCAL_PATH.search(line):
            findings.append(
                Finding(display, number, "developer-machine path is prohibited")
            )
        for match in EMAIL.finditer(line):
            if not _is_safe_email(match.group(0)):
                findings.append(
                    Finding(
                        display,
                        number,
                        "personal or non-placeholder email is prohibited",
                    )
                )
    return findings


def scan_repository(root: Path) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for directory, child_directories, filenames in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        child_directories[:] = sorted(
            name for name in child_directories if name not in SKIP_PARTS
        )
        current = Path(directory)
        for filename in sorted(filenames):
            path = current / filename
            if not path.is_file() or any(
                part in SKIP_PARTS for part in path.relative_to(root).parts
            ):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            findings.extend(scan_text(text, path.relative_to(root).as_posix()))
    return sorted(set(findings))


def scan_git_history(root: Path) -> list[Finding]:
    process = subprocess.run(
        ["git", "log", "--all", "--format=%H%x09%ae%x09%ce"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        return [Finding(".git", 1, "could not inspect Git identity metadata")]

    findings: list[Finding] = []
    for line in process.stdout.splitlines():
        commit, author_email, committer_email = line.split("\t", maxsplit=2)
        if not _is_safe_email(author_email):
            findings.append(
                Finding(
                    ".git", 1, f"commit {commit[:12]} author must use GitHub no-reply"
                )
            )
        if not _is_safe_email(committer_email):
            findings.append(
                Finding(
                    ".git",
                    1,
                    f"commit {commit[:12]} committer must use GitHub no-reply",
                )
            )
    return sorted(set(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument("--git-history", action="store_true")
    args = parser.parse_args(argv)

    findings = scan_repository(args.root)
    if args.git_history:
        findings.extend(scan_git_history(args.root.resolve()))
    if findings:
        print("Privacy policy violations:", file=sys.stderr)
        for finding in sorted(set(findings)):
            print(f"  {finding.render()}", file=sys.stderr)
        return 1
    print("Privacy policy scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
