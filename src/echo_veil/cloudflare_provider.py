"""Cloudflare Access/Workers transport for an attested enclave provider.

Cloudflare is the authenticated edge gateway, not the source of enclave trust.
Attestation evidence is returned unchanged and must be checked by the configured
``AttestationVerifier`` used by :class:`EnclaveCryptoShield`.
"""

from __future__ import annotations

import base64
import hmac
import json
import math
import os
import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping
from numbers import Real
from typing import Protocol
from urllib.parse import urljoin, urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ._json import require_exact_keys, strict_json_loads
from .crypto_shield import VerifiedEnclave
from .vectors import Vector, as_vector

MAX_GATEWAY_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_GATEWAY_TIMEOUT_SECONDS = 60.0
MAX_ACCESS_CREDENTIAL_BYTES = 16 * 1024
MAX_ENCLAVE_VECTOR_ELEMENTS = 16_384
MAX_PROOF_BYTES = 4_096
MAX_SESSION_CHARS = 4_096


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        return None


class CloudflareGatewayError(RuntimeError):
    """A sanitized gateway failure that never includes an upstream body."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)


class CloudflareTransport(Protocol):
    def post(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> bytes:
        raise NotImplementedError


class UrllibCloudflareTransport:
    """Small standard-library HTTPS transport with bounded responses."""

    def __init__(self, ssl_context: ssl.SSLContext | None = None) -> None:
        self._ssl_context = ssl_context or ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_context),
            _NoRedirectHandler(),
        )

    def post(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> bytes:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("Cloudflare transport only permits absolute HTTPS URLs")
        request = urllib.request.Request(
            url,
            data=body,
            headers=dict(headers),
            method="POST",
        )
        try:
            # URL is revalidated immediately above as absolute HTTPS only.
            with self._opener.open(request, timeout=timeout_seconds) as response:
                declared_length = response.headers.get("Content-Length")
                if declared_length is not None:
                    if (
                        not declared_length.isascii()
                        or not declared_length.isdigit()
                        or int(declared_length) > MAX_GATEWAY_RESPONSE_BYTES
                    ):
                        raise CloudflareGatewayError(
                            "Cloudflare enclave gateway returned an invalid response size"
                        )
                content_type = response.headers.get("Content-Type", "")
                if content_type.split(";", 1)[0].strip().lower() != "application/json":
                    raise CloudflareGatewayError(
                        "Cloudflare enclave gateway returned an invalid content type"
                    )
                payload = response.read(MAX_GATEWAY_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise CloudflareGatewayError(
                "Cloudflare enclave gateway rejected the request",
                status_code=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise CloudflareGatewayError(
                "Cloudflare enclave gateway is unavailable"
            ) from exc
        if len(payload) > MAX_GATEWAY_RESPONSE_BYTES:
            raise CloudflareGatewayError(
                "Cloudflare enclave gateway response is too large"
            )
        return payload


class CloudflareEnclaveProvider:
    """Implement ``EnclaveProvider`` through a Cloudflare Access Worker.

    The Access client secret is sent only in the documented service-token
    header. The Worker then uses its mTLS binding to call the actual enclave.
    """

    _base_url: str
    _headers: dict[str, str]
    _timeout: float
    _transport: CloudflareTransport
    _enclave_transport_key: X25519PublicKey | None

    def __init__(
        self,
        gateway_url: str,
        access_client_id: str,
        access_client_secret: str,
        *,
        timeout_seconds: float = 10.0,
        transport: CloudflareTransport | None = None,
    ) -> None:
        parsed = urlparse(gateway_url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.hostname is None:
            raise ValueError("gateway_url must be an absolute HTTPS URL")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("gateway_url contains an invalid port") from exc
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("gateway_url must be a credential-free HTTPS origin")
        self._validate_access_credential(access_client_id, "client ID")
        self._validate_access_credential(access_client_secret, "client secret")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, Real):
            raise TypeError("timeout_seconds must be a finite positive number")
        timeout = float(timeout_seconds)
        if (
            not math.isfinite(timeout)
            or timeout <= 0.0
            or timeout > MAX_GATEWAY_TIMEOUT_SECONDS
        ):
            raise ValueError(
                f"timeout_seconds must be within (0, {MAX_GATEWAY_TIMEOUT_SECONDS:g}]"
            )
        self._base_url = gateway_url.rstrip("/") + "/"
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "CF-Access-Client-Id": access_client_id,
            "CF-Access-Client-Secret": access_client_secret,
        }
        self._timeout = timeout
        self._transport = transport or UrllibCloudflareTransport()
        self._enclave_transport_key = None

    @classmethod
    def from_env(
        cls,
        gateway_url: str,
        *,
        client_id_env: str = "CF_ACCESS_CLIENT_ID",
        client_secret_env: str = "CF_ACCESS_CLIENT_SECRET",
        timeout_seconds: float = 10.0,
    ) -> CloudflareEnclaveProvider:
        """Load Access service-token credentials from environment variables."""
        client_id = os.environ.get(client_id_env, "")
        client_secret = os.environ.get(client_secret_env, "")
        if not client_id or not client_secret:
            raise ValueError(
                f"{client_id_env} and {client_secret_env} must both be set"
            )
        return cls(
            gateway_url,
            client_id,
            client_secret,
            timeout_seconds=timeout_seconds,
        )

    def attest(self, nonce: bytes) -> bytes:
        if not isinstance(nonce, bytes) or not 16 <= len(nonce) <= 256:
            raise ValueError("attestation nonce must contain 16..256 bytes")
        return self._decode_bytes(
            self._post("v1/attest", {"nonce_b64": self._encode_bytes(nonce)}),
            "evidence_b64",
            maximum=65_536,
        )

    def bind_attestation(self, enclave: VerifiedEnclave) -> None:
        """Bind the verified enclave E2E transport key to subsequent requests."""
        self._enclave_transport_key = X25519PublicKey.from_public_bytes(
            enclave.transport_public_key
        )

    def access_challenge(self) -> bytes:
        challenge = self._decode_bytes(
            self._secure_post("v1/challenge", {}),
            "challenge_b64",
            maximum=256,
        )
        if len(challenge) < 32:
            raise RuntimeError("enclave gateway returned an invalid challenge")
        return challenge

    def open_session(self, proof: bytes) -> str:
        if not isinstance(proof, bytes) or not 0 < len(proof) <= MAX_PROOF_BYTES:
            raise ValueError("enclave proof exceeds the safety limit")
        value = self._secure_post(
            "v1/session", {"proof_b64": self._encode_bytes(proof)}
        )
        session = value.get("session")
        if (
            not isinstance(session, str)
            or not 0 < len(session) <= MAX_SESSION_CHARS
            or any(not 33 <= ord(character) <= 126 for character in session)
        ):
            raise RuntimeError("enclave gateway returned an invalid session")
        return session

    def encrypt_vector(self, session: str, anchor: Vector) -> bytes:
        self._validate_session(session)
        vector = as_vector(anchor, allow_empty=False, name="anchor vector")
        if vector.size > MAX_ENCLAVE_VECTOR_ELEMENTS:
            raise ValueError("anchor vector exceeds the enclave safety limit")
        value = self._secure_post(
            "v1/vector/encrypt",
            {"session": session, "vector": vector.tolist()},
        )
        return self._decode_bytes(value, "ciphertext_b64")

    def cosine_similarity(
        self, session: str, intent: Vector, ciphertext: bytes
    ) -> float:
        self._validate_session(session)
        if (
            not isinstance(ciphertext, bytes)
            or not 0 < len(ciphertext) <= MAX_GATEWAY_RESPONSE_BYTES
        ):
            raise ValueError("enclave ciphertext exceeds the safety limit")
        vector = as_vector(intent, allow_empty=False, name="intent vector")
        if vector.size > MAX_ENCLAVE_VECTOR_ELEMENTS:
            raise ValueError("intent vector exceeds the enclave safety limit")
        value = self._secure_post(
            "v1/vector/similarity",
            {
                "session": session,
                "intent": vector.tolist(),
                "ciphertext_b64": self._encode_bytes(ciphertext),
            },
        )
        score = value.get("score")
        if isinstance(score, bool) or not isinstance(score, Real):
            raise RuntimeError("enclave gateway returned an invalid similarity score")
        result = float(score)
        if not math.isfinite(result):
            raise RuntimeError("enclave gateway returned a non-finite similarity score")
        return result

    def _post(self, path: str, payload: Mapping[str, object]) -> dict[str, object]:
        body = json.dumps(
            dict(payload), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        raw = self._transport.post(
            urljoin(self._base_url, path), self._headers, body, self._timeout
        )
        try:
            decoded = strict_json_loads(raw)
        except Exception as exc:
            raise RuntimeError("enclave gateway returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("enclave gateway response must be a JSON object")
        try:
            require_exact_keys(
                decoded,
                {"evidence_b64"}
                if path == "v1/attest"
                else {"nonce_b64", "ciphertext_b64"},
            )
        except ValueError as exc:
            raise RuntimeError("enclave gateway response schema is invalid") from exc
        return decoded

    def _secure_post(
        self, path: str, payload: Mapping[str, object]
    ) -> dict[str, object]:
        if self._enclave_transport_key is None:
            raise RuntimeError("verified enclave transport key is not bound")
        aad_path = "/" + path.lstrip("/")
        ephemeral = X25519PrivateKey.generate()
        shared = ephemeral.exchange(self._enclave_transport_key)
        request_nonce = os.urandom(12)
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=request_nonce,
            info=b"echo-veil-cloudflare-envelope-v1:" + aad_path.encode("ascii"),
        ).derive(shared)
        plaintext = json.dumps(
            dict(payload), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        request_ciphertext = AESGCM(key).encrypt(
            request_nonce, plaintext, aad_path.encode("ascii")
        )
        public_key = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        envelope = self._post(
            path,
            {
                "ephemeral_public_key_b64": self._encode_bytes(public_key),
                "nonce_b64": self._encode_bytes(request_nonce),
                "ciphertext_b64": self._encode_bytes(request_ciphertext),
            },
        )
        response_nonce = self._decode_bytes(envelope, "nonce_b64")
        if len(response_nonce) != 12:
            raise RuntimeError("enclave gateway returned an invalid response nonce")
        response_ciphertext = self._decode_bytes(envelope, "ciphertext_b64")
        try:
            response_plaintext = AESGCM(key).decrypt(
                response_nonce,
                response_ciphertext,
                aad_path.encode("ascii") + b":response",
            )
            decoded = strict_json_loads(response_plaintext)
        except Exception as exc:
            raise RuntimeError(
                "enclave response envelope authentication failed"
            ) from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("enclave response envelope must contain a JSON object")
        expected = {
            "v1/challenge": {"challenge_b64"},
            "v1/session": {"session"},
            "v1/vector/encrypt": {"ciphertext_b64"},
            "v1/vector/similarity": {"score"},
        }.get(path)
        if expected is None:
            raise RuntimeError("unsupported secure enclave path")
        try:
            require_exact_keys(decoded, expected)
        except ValueError as exc:
            raise RuntimeError("enclave response payload schema is invalid") from exc
        return decoded

    @staticmethod
    def _validate_access_credential(value: str, label: str) -> None:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or len(value.encode("utf-8")) > MAX_ACCESS_CREDENTIAL_BYTES
            or any(not 33 <= ord(character) <= 126 for character in value)
        ):
            raise ValueError(f"Cloudflare Access {label} is invalid")

    @staticmethod
    def _validate_session(value: str) -> None:
        if (
            not isinstance(value, str)
            or not 0 < len(value) <= MAX_SESSION_CHARS
            or any(not 33 <= ord(character) <= 126 for character in value)
        ):
            raise ValueError("enclave session is invalid")

    @staticmethod
    def _encode_bytes(value: bytes) -> str:
        if not isinstance(value, bytes) or not value:
            raise ValueError("binary enclave values must be non-empty bytes")
        return base64.urlsafe_b64encode(value).decode("ascii")

    @staticmethod
    def _decode_bytes(
        payload: Mapping[str, object],
        field: str,
        *,
        maximum: int = MAX_GATEWAY_RESPONSE_BYTES,
    ) -> bytes:
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"enclave gateway response is missing {field}")
        try:
            encoded = value.encode("ascii")
            decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
        except Exception as exc:
            raise RuntimeError(f"enclave gateway returned invalid {field}") from exc
        if (
            not decoded
            or len(decoded) > maximum
            or not hmac.compare_digest(base64.urlsafe_b64encode(decoded), encoded)
        ):
            raise RuntimeError(f"enclave gateway returned invalid {field}")
        return decoded
