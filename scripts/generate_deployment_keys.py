#!/usr/bin/env python3
"""Generate offline deployment keys without printing or overwriting secrets."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_new(path: Path, value: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(value)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def b64(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value)


def raw_private(  # gitleaks:allow -- function handles generated key objects, not a literal
    key: X25519PrivateKey | Ed25519PrivateKey,  # gitleaks:allow -- type name only
) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def generate_mtls(directory: Path) -> None:
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Echo Veil Worker mTLS CA")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA384())
    )
    client_key = ec.generate_private_key(ec.SECP384R1())
    client_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Algo CLI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "echo-veil-cloudflare-worker"),
        ]
    )
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA384())
    )
    write_new(
        directory / "cloudflare-mtls-client-ca.pem",
        ca_cert.public_bytes(serialization.Encoding.PEM),
    )
    write_new(
        directory / "cloudflare-mtls-client.pem",
        client_cert.public_bytes(serialization.Encoding.PEM),
    )
    write_new(
        directory / "cloudflare-mtls-client.key",
        client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--zkp-binary", type=Path, required=True)
    args = parser.parse_args()
    output: Path = args.output.resolve()
    if output.exists():
        raise SystemExit("refusing to use an existing output directory")
    output.mkdir(mode=0o700, parents=True)

    transport = X25519PrivateKey.generate()
    attestation = Ed25519PrivateKey.generate()
    write_new(output / "transport-x25519.key", b64(raw_private(transport)))
    write_new(output / "attestation-ed25519.key", b64(raw_private(attestation)))
    write_new(output / "origin-token", secrets.token_urlsafe(48).encode("ascii"))
    write_new(
        output / "attestation-ed25519.pub",
        b64(
            attestation.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ),
    )
    write_new(
        output / "transport-x25519.pub",
        b64(
            transport.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ),
    )
    completed = subprocess.run(
        [
            str(args.zkp_binary.resolve()),
            "keygen",
            "--key-file",
            str(output / "zkp.key"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10.0,
        close_fds=True,
    )
    if completed.returncode != 0:
        raise SystemExit("Ristretto key generation failed")
    try:
        public_key = json.loads(completed.stdout)["public_key_b64"]
        if not isinstance(public_key, str):
            raise TypeError
        base64.b64decode(public_key.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise SystemExit("Ristretto key generator returned invalid output") from exc
    write_new(
        output / "allowed-zkp-public-keys.json",
        (json.dumps([public_key], indent=2) + "\n").encode("utf-8"),
    )
    generate_mtls(output)
    manifest = {
        "created_at": datetime.now(UTC).isoformat(),
        "files": sorted(path.name for path in output.iterdir()),
        "public": {
            "attestation_ed25519": (output / "attestation-ed25519.pub")
            .read_text()
            .strip(),
            "transport_x25519": (output / "transport-x25519.pub").read_text().strip(),
            "zkp_ristretto255": public_key,
        },
    }
    write_new(
        output / "manifest.json",
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(f"Created deployment material in {output}")
    print(
        "Secrets were not printed. Transfer them through the approved secret channel."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
