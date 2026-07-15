from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts.secure_bundle import unwrap_bundle, wrap_directory


def _keys(tmp_path: Path) -> tuple[Path, Path]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path = tmp_path / "release-private.pem"
    public_path = tmp_path / "release-public.pem"
    private_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return public_path, private_path


def test_secure_bundle_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    (source / "origin-token").write_bytes(b"secret-token")
    (source / "allowed.json").write_text('["public"]', encoding="utf-8")
    public_key, private_key = _keys(tmp_path)
    bundle = tmp_path / "bundle.json"
    output = tmp_path / "output"

    wrap_directory(source, public_key, bundle)
    assert b"secret-token" not in bundle.read_bytes()
    unwrap_bundle(bundle, private_key, output)

    assert (output / "origin-token").read_bytes() == b"secret-token"
    assert (output / "allowed.json").read_text() == '["public"]'
    assert (output / "origin-token").stat().st_mode & 0o077 == 0


def test_secure_bundle_rejects_tampering(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "secret").write_bytes(b"value")
    public_key, private_key = _keys(tmp_path)
    bundle = tmp_path / "bundle.json"
    wrap_directory(source, public_key, bundle)
    value = json.loads(bundle.read_text())
    value["ciphertext_b64"] = value["ciphertext_b64"][:-2] + "AA"
    bundle.write_text(json.dumps(value))

    with pytest.raises(ValueError, match="authentication"):
        unwrap_bundle(bundle, private_key, tmp_path / "output")


def test_secure_bundle_rejects_symlink_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    target = tmp_path / "target"
    target.write_bytes(b"secret")
    (source / "linked-secret").symlink_to(target)
    public_key, _ = _keys(tmp_path)

    with pytest.raises(ValueError, match="regular files"):
        wrap_directory(source, public_key, tmp_path / "bundle.json")
