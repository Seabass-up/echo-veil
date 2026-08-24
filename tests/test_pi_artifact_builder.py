from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

import pytest

from echo_veil import guarded_runner
from scripts import build_pi_artifact_receipt


ROOT = Path(__file__).resolve().parents[1]


def _copy_artifact(tmp_path: Path) -> Path:
    destination = tmp_path / "pi"
    destination.mkdir(mode=0o700)
    source = ROOT / "integrations" / "pi"
    for name in guarded_runner.PI_ARTIFACT_FILES:
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(source / name, target)
    return destination


def test_pi_receipt_builder_round_trips_through_both_verifiers(
    tmp_path: Path,
) -> None:
    artifact = _copy_artifact(tmp_path)

    written = build_pi_artifact_receipt.run(artifact, check=False)
    authority = str(written["artifact_authority_id"])

    assert build_pi_artifact_receipt.run(artifact, check=True)["status"] == "verified"
    assert guarded_runner._verify_pi_artifact(artifact, authority) == authority
    receipt = json.loads((artifact / "artifact-receipt.json").read_text())
    assert receipt["package_version"] == guarded_runner.PI_PACKAGE_VERSION
    assert len(receipt["files"]) == len(guarded_runner.PI_ARTIFACT_FILES)


def test_pi_receipt_check_rejects_one_byte_drift(tmp_path: Path) -> None:
    artifact = _copy_artifact(tmp_path)
    build_pi_artifact_receipt.run(artifact, check=False)
    with (artifact / "src" / "runner.ts").open("ab") as stream:
        stream.write(b"\n")

    with pytest.raises(RuntimeError, match="does not match"):
        build_pi_artifact_receipt.run(artifact, check=True)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink input contract")
def test_pi_receipt_builder_rejects_symlink_directory(tmp_path: Path) -> None:
    artifact = _copy_artifact(tmp_path)
    linked = tmp_path / "linked"
    linked.symlink_to(artifact, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        build_pi_artifact_receipt.build_receipt(linked)
