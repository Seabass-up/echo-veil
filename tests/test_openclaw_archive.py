from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

from scripts.build_openclaw_archive import ARCHIVE_FILES, build_archive


ROOT = Path(__file__).resolve().parents[1]


def test_openclaw_archive_is_reproducible_and_bound_to_release_lock(
    tmp_path: Path,
) -> None:
    lock = json.loads(
        (ROOT / "integrations/openclaw/deployment-lock.json").read_text(
            encoding="utf-8"
        )
    )
    epoch = lock["source_date_epoch"]
    first = build_archive(
        ROOT / "integrations/openclaw",
        tmp_path / "first",
        epoch,
    )
    second = build_archive(
        ROOT / "integrations/openclaw",
        tmp_path / "second",
        epoch,
    )

    assert first.read_bytes() == second.read_bytes()
    assert (
        hashlib.sha256(first.read_bytes()).hexdigest()
        == lock["plugin"]["archive_sha256"]
    )

    with tarfile.open(first, "r:gz") as archive:
        members = archive.getmembers()
        assert [member.name for member in members] == [
            f"package/{relative}" for relative in sorted(ARCHIVE_FILES)
        ]
        assert all(member.isfile() for member in members)
        assert all(member.mtime == epoch for member in members)
        assert all(member.uid == 0 and member.gid == 0 for member in members)
        assert all(member.uname == "" and member.gname == "" for member in members)
        assert all(member.mode == 0o644 for member in members)
