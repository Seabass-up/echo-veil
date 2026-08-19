"""Offline verification of pinned Microsoft Azure Attestation JWT evidence."""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
from pathlib import Path
import stat
import time
from collections.abc import Mapping
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ._json import strict_json_loads

MAX_MAA_TOKEN_BYTES = 65_536
MAX_MAA_JWKS_BYTES = 128 * 1024


def _decode_jwt_part(value: object, label: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum or "=" in value:
        raise ValueError(f"invalid {label}")
    try:
        encoded = value.encode("ascii")
        decoded = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    except Exception as exc:
        raise ValueError(f"invalid {label}") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=")
    if not decoded or not hmac.compare_digest(canonical, encoded):
        raise ValueError(f"invalid {label}")
    return decoded


def _bounded_string(value: object, label: str, maximum: int = 2_048) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"invalid {label}")
    return value


def _numeric_date(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"invalid {label}")
    output = float(value)
    if not math.isfinite(output) or output < 0.0:
        raise ValueError(f"invalid {label}")
    return output


def _lower_hex(value: object, label: str, length: int) -> str:
    text = _bounded_string(value, label, length)
    if len(text) != length or any(
        character not in "0123456789abcdef" for character in text
    ):
        raise ValueError(f"invalid {label}")
    return text


class AzureMaaJwtVerifier:
    """Verify a fresh SEV-SNP MAA token against an offline pinned JWKS."""

    def __init__(
        self,
        issuer: str,
        keys: Mapping[str, rsa.RSAPublicKey],
        *,
        maximum_lifetime_seconds: float = 300.0,
        clock_skew_seconds: float = 30.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._issuer = _bounded_string(issuer, "MAA issuer", 2_048)
        if not self._issuer.startswith("https://") or self._issuer.endswith("/"):
            raise ValueError("MAA issuer must be a canonical HTTPS origin")
        if (
            not keys
            or len(keys) > 32
            or not all(
                isinstance(key_id, str)
                and 0 < len(key_id) <= 512
                and isinstance(public_key, rsa.RSAPublicKey)
                for key_id, public_key in keys.items()
            )
        ):
            raise ValueError("MAA signing keys are invalid")
        if (
            isinstance(maximum_lifetime_seconds, bool)
            or not isinstance(maximum_lifetime_seconds, (int, float))
            or not 0.0 < float(maximum_lifetime_seconds) <= 600.0
        ):
            raise ValueError("MAA maximum lifetime must be within (0, 600]")
        if (
            isinstance(clock_skew_seconds, bool)
            or not isinstance(clock_skew_seconds, (int, float))
            or not 0.0 <= float(clock_skew_seconds) <= 60.0
        ):
            raise ValueError("MAA clock skew must be within [0, 60]")
        self._keys = dict(keys)
        self._maximum_lifetime = float(maximum_lifetime_seconds)
        self._clock_skew = float(clock_skew_seconds)
        self._clock = clock

    @classmethod
    def from_jwks_file(
        cls,
        issuer: str,
        path: str | os.PathLike[str],
        **kwargs: Any,
    ) -> AzureMaaJwtVerifier:
        candidate = Path(path).expanduser().absolute()
        if any(component.is_symlink() for component in (candidate, *candidate.parents)):
            raise RuntimeError("MAA JWKS path must not contain symbolic links")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(candidate, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("MAA JWKS must be a regular file")
            if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o022:
                raise RuntimeError("MAA JWKS must not be group/world writable")
            if not 0 < info.st_size <= MAX_MAA_JWKS_BYTES:
                raise RuntimeError("MAA JWKS size is invalid")
            raw = os.read(descriptor, MAX_MAA_JWKS_BYTES + 1)
        finally:
            os.close(descriptor)
        try:
            value = strict_json_loads(raw)
            if not isinstance(value, dict) or set(value) != {"keys"}:
                raise ValueError
            entries = value["keys"]
            if not isinstance(entries, list) or not 0 < len(entries) <= 32:
                raise ValueError
            keys: dict[str, rsa.RSAPublicKey] = {}
            for entry in entries:
                if not isinstance(entry, dict):
                    raise ValueError
                kid = _bounded_string(entry.get("kid"), "JWK kid", 512)
                if (
                    kid in keys
                    or entry.get("kty") != "RSA"
                    or entry.get("alg") != "RS256"
                ):
                    raise ValueError
                if entry.get("use", "sig") != "sig":
                    raise ValueError
                modulus = int.from_bytes(
                    _decode_jwt_part(entry.get("n"), "JWK modulus", maximum=2_048),
                    "big",
                )
                exponent = int.from_bytes(
                    _decode_jwt_part(entry.get("e"), "JWK exponent", maximum=32),
                    "big",
                )
                if modulus.bit_length() < 2_048 or exponent < 3 or exponent % 2 == 0:
                    raise ValueError
                keys[kid] = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        except Exception as exc:
            raise RuntimeError("MAA JWKS is invalid") from exc
        return cls(issuer, keys, **kwargs)

    def verify(
        self,
        evidence: bytes,
        runtime_data: bytes,
        *,
        launch_measurement: str,
        cce_policy_hash: str,
        maa_policy_hash: str,
    ) -> Mapping[str, object]:
        try:
            if (
                not isinstance(evidence, bytes)
                or not 0 < len(evidence) <= MAX_MAA_TOKEN_BYTES
            ):
                raise ValueError
            if (
                not isinstance(runtime_data, bytes)
                or not 0 < len(runtime_data) <= 8_192
            ):
                raise ValueError
            token = evidence.decode("ascii")
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError
            header_value = strict_json_loads(
                _decode_jwt_part(parts[0], "JWT header", maximum=8_192)
            )
            claims_value = strict_json_loads(
                _decode_jwt_part(parts[1], "JWT payload", maximum=MAX_MAA_TOKEN_BYTES)
            )
            if not isinstance(header_value, dict) or not isinstance(claims_value, dict):
                raise ValueError
            if header_value.get("alg") != "RS256" or header_value.get("typ") != "JWT":
                raise ValueError
            key_id = _bounded_string(header_value.get("kid"), "JWT kid", 512)
            key = self._keys.get(key_id)
            if key is None:
                raise ValueError
            signature = _decode_jwt_part(parts[2], "JWT signature", maximum=2_048)
            key.verify(
                signature,
                f"{parts[0]}.{parts[1]}".encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except Exception as exc:
            raise ValueError(
                "native MAA evidence signature or format is invalid"
            ) from exc

        now = self._clock()
        issued_at = _numeric_date(claims_value.get("iat"), "MAA iat")
        not_before = _numeric_date(claims_value.get("nbf"), "MAA nbf")
        expires_at = _numeric_date(claims_value.get("exp"), "MAA exp")
        if (
            issued_at > now + self._clock_skew
            or not_before > now + self._clock_skew
            or expires_at <= now - self._clock_skew
            or expires_at < issued_at
            or expires_at - issued_at > self._maximum_lifetime
        ):
            raise ValueError("native MAA evidence is not fresh")
        if claims_value.get("iss") != self._issuer:
            raise ValueError("native MAA issuer is not approved")
        if (
            claims_value.get("x-ms-attestation-type") != "sevsnpvm"
            or claims_value.get("x-ms-compliance-status") != "azure-compliant-uvm"
            or claims_value.get("x-ms-sevsnpvm-is-debuggable") is not False
            or claims_value.get("x-ms-sevsnpvm-migration-allowed") is not False
            or claims_value.get("x-ms-sevsnpvm-vmpl") != 0
        ):
            raise ValueError("native MAA hardware claims are invalid")
        if claims_value.get("x-ms-policy-hash") != maa_policy_hash:
            raise ValueError("native MAA policy hash is not approved")
        if claims_value.get("x-ms-sevsnpvm-hostdata") != cce_policy_hash:
            raise ValueError("native CCE policy hash is not approved")
        if claims_value.get("x-ms-sevsnpvm-launchmeasurement") != launch_measurement:
            raise ValueError("native launch measurement is not approved")
        report_data = _lower_hex(
            claims_value.get("x-ms-sevsnpvm-reportdata"),
            "SNP report data",
            128,
        )
        expected_hash = hashlib.sha256(runtime_data).hexdigest()
        if (
            not hmac.compare_digest(report_data[:64], expected_hash)
            or report_data[64:] != "0" * 64
        ):
            raise ValueError("native MAA evidence is not bound to runtime data")
        return claims_value
