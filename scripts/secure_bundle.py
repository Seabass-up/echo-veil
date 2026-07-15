#!/usr/bin/env python3
"""Wrap deployment material to an Azure SKR RSA key and unwrap inside the CVM."""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import shutil
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"echo-veil-deployment-bundle-v1"
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: object, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid {label}")
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError(f"invalid {label}") from exc
    if not decoded or len(decoded) > maximum:
        raise ValueError(f"invalid {label}")
    return decoded


def _jwk_int(value: object, label: str) -> int:
    return int.from_bytes(_unb64(value, label, 8192), "big")


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    raw = path.read_bytes()
    try:
        key = serialization.load_pem_public_key(raw)
    except ValueError:
        try:
            value = json.loads(raw)
            key = rsa.RSAPublicNumbers(
                _jwk_int(value["e"], "e"), _jwk_int(value["n"], "n")
            ).public_key()
        except Exception as exc:
            raise ValueError("public key must be RSA PEM or JWK") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise ValueError("wrapping key must be RSA with at least 3072 bits")
    return key


def load_private_key(path: Path) -> rsa.RSAPrivateKey:
    raw = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except ValueError:
        try:
            value = json.loads(raw)
            public = rsa.RSAPublicNumbers(
                _jwk_int(value["e"], "e"), _jwk_int(value["n"], "n")
            )
            key = rsa.RSAPrivateNumbers(
                p=_jwk_int(value["p"], "p"),
                q=_jwk_int(value["q"], "q"),
                d=_jwk_int(value["d"], "d"),
                dmp1=_jwk_int(value["dp"], "dp"),
                dmq1=_jwk_int(value["dq"], "dq"),
                iqmp=_jwk_int(value["qi"], "qi"),
                public_numbers=public,
            ).private_key()
        except Exception as exc:
            raise ValueError("private key must be RSA PEM or private JWK") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
        raise ValueError("release key must be RSA with at least 3072 bits")
    return key


def _archive_directory(source: Path) -> bytes:
    files = sorted(source.iterdir())
    if not files or any(not path.is_file() or path.is_symlink() for path in files):
        raise ValueError("bundle source must contain only regular files")
    total = sum(path.stat().st_size for path in files)
    if total > MAX_SOURCE_BYTES:
        raise ValueError("bundle source exceeds the safety limit")
    output = io.BytesIO()
    with tarfile.open(
        fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT
    ) as archive:
        for path in files:
            data = path.read_bytes()
            member = tarfile.TarInfo(path.name)
            member.size = len(data)
            member.mode = 0o600
            member.mtime = 0
            member.uid = 0
            member.gid = 0
            archive.addfile(member, io.BytesIO(data))
    value = output.getvalue()
    if len(value) > MAX_SOURCE_BYTES:
        raise ValueError("compressed bundle exceeds the safety limit")
    return value


def wrap_directory(source: Path, public_key_path: Path, output_path: Path) -> None:
    source = source.resolve()
    if not source.is_dir():
        raise ValueError("bundle source directory does not exist")
    if output_path.exists():
        raise ValueError("refusing to overwrite an existing bundle")
    plaintext = _archive_directory(source)
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, AAD)
    wrapped_key = load_public_key(public_key_path).encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=AAD,
        ),
    )
    envelope = json.dumps(
        {
            "algorithm": "RSA-OAEP-SHA256+A256GCM",
            "ciphertext_b64": _b64(ciphertext),
            "nonce_b64": _b64(nonce),
            "version": 1,
            "wrapped_key_b64": _b64(wrapped_key),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(envelope)


def unwrap_bundle(bundle_path: Path, private_key_path: Path, output: Path) -> None:
    if output.exists():
        raise ValueError("refusing to use an existing output directory")
    if bundle_path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("wrapped bundle exceeds the safety limit")
    try:
        envelope = json.loads(bundle_path.read_bytes())
        if envelope.get("version") != 1 or envelope.get("algorithm") != (
            "RSA-OAEP-SHA256+A256GCM"
        ):
            raise ValueError("unsupported bundle format")
        wrapped_key = _unb64(envelope.get("wrapped_key_b64"), "wrapped key", 8192)
        nonce = _unb64(envelope.get("nonce_b64"), "nonce", 12)
        ciphertext = _unb64(
            envelope.get("ciphertext_b64"), "ciphertext", MAX_BUNDLE_BYTES
        )
        if len(nonce) != 12:
            raise ValueError("invalid nonce")
        data_key = load_private_key(private_key_path).decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=AAD,
            ),
        )
        plaintext = AESGCM(data_key).decrypt(nonce, ciphertext, AAD)
    except Exception as exc:
        raise ValueError("bundle authentication or key unwrap failed") from exc
    output.mkdir(mode=0o700, parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 1000:
                raise ValueError("invalid archive member count")
            for member in members:
                if (
                    not member.isfile()
                    or Path(member.name).name != member.name
                    or member.size > MAX_SOURCE_BYTES
                ):
                    raise ValueError("unsafe archive member")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError("invalid archive member")
                data = extracted.read(MAX_SOURCE_BYTES + 1)
                if len(data) != member.size or len(data) > MAX_SOURCE_BYTES:
                    raise ValueError("invalid archive member size")
                descriptor = os.open(
                    output / member.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as target:
                    target.write(data)
    except Exception:
        shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    wrap = commands.add_parser("wrap")
    wrap.add_argument("--source", type=Path, required=True)
    wrap.add_argument("--public-key", type=Path, required=True)
    wrap.add_argument("--output", type=Path, required=True)
    unwrap = commands.add_parser("unwrap")
    unwrap.add_argument("--bundle", type=Path, required=True)
    unwrap.add_argument("--private-key", type=Path, required=True)
    unwrap.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "wrap":
        wrap_directory(args.source, args.public_key, args.output)
        print(f"Wrote encrypted bundle to {args.output}")
    else:
        unwrap_bundle(args.bundle, args.private_key, args.output)
        print(f"Unwrapped deployment material into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
