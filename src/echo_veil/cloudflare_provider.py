"""Cloudflare Access/Workers transport for an attested enclave provider.

Cloudflare is the authenticated edge gateway, not the source of enclave trust.
Attestation evidence is returned unchanged and must be checked by the configured
``AttestationVerifier`` used by :class:`EnclaveCryptoShield`.
"""

from __future__ import annotations

import base64
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

from .crypto_shield import VerifiedEnclave
from .vectors import Vector, as_vector

MAX_GATEWAY_RESPONSE_BYTES = 16 * 1024 * 1024


class CloudflareTransport(Protocol):
    def post(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> bytes: ...


class UrllibCloudflareTransport:
    """Small standard-library HTTPS transport with bounded responses."""

    def __init__(self, ssl_context: ssl.SSLContext | None = None) -> None:
        self._ssl_context = ssl_context or ssl.create_default_context()

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
            with urllib.request.urlopen(  # nosec B310
                request, timeout=timeout_seconds, context=self._ssl_context
            ) as response:
                payload = response.read(MAX_GATEWAY_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Cloudflare enclave gateway rejected the request ({exc.code}): {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError("Cloudflare enclave gateway is unavailable") from exc
        if len(payload) > MAX_GATEWAY_RESPONSE_BYTES:
            raise RuntimeError("Cloudflare enclave gateway response is too large")
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
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("gateway_url must be an absolute HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                "gateway_url must not contain credentials, query, or fragment"
            )
        if not access_client_id.strip() or not access_client_secret.strip():
            raise ValueError("Cloudflare Access service-token credentials are required")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, Real):
            raise TypeError("timeout_seconds must be a finite positive number")
        timeout = float(timeout_seconds)
        if not math.isfinite(timeout) or timeout <= 0.0:
            raise ValueError("timeout_seconds must be a finite positive number")
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
        return self._decode_bytes(
            self._post("v1/attest", {"nonce_b64": self._encode_bytes(nonce)}),
            "evidence_b64",
        )

    def bind_attestation(self, enclave: VerifiedEnclave) -> None:
        """Bind the verified enclave E2E transport key to subsequent requests."""
        self._enclave_transport_key = X25519PublicKey.from_public_bytes(
            enclave.transport_public_key
        )

    def access_challenge(self) -> bytes:
        return self._decode_bytes(
            self._secure_post("v1/challenge", {}), "challenge_b64"
        )

    def open_session(self, proof: bytes) -> str:
        value = self._secure_post(
            "v1/session", {"proof_b64": self._encode_bytes(proof)}
        )
        session = value.get("session")
        if not isinstance(session, str) or not session:
            raise RuntimeError("enclave gateway returned an invalid session")
        return session

    def encrypt_vector(self, session: str, anchor: Vector) -> bytes:
        vector = as_vector(anchor, allow_empty=False, name="anchor vector")
        value = self._secure_post(
            "v1/vector/encrypt",
            {"session": session, "vector": vector.tolist()},
        )
        return self._decode_bytes(value, "ciphertext_b64")

    def cosine_similarity(
        self, session: str, intent: Vector, ciphertext: bytes
    ) -> float:
        vector = as_vector(intent, allow_empty=False, name="intent vector")
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
            decoded = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError("enclave gateway returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("enclave gateway response must be a JSON object")
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
            decoded = json.loads(response_plaintext.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                "enclave response envelope authentication failed"
            ) from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("enclave response envelope must contain a JSON object")
        return decoded

    @staticmethod
    def _encode_bytes(value: bytes) -> str:
        if not isinstance(value, bytes) or not value:
            raise ValueError("binary enclave values must be non-empty bytes")
        return base64.urlsafe_b64encode(value).decode("ascii")

    @staticmethod
    def _decode_bytes(payload: Mapping[str, object], field: str) -> bytes:
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise RuntimeError(f"enclave gateway response is missing {field}")
        try:
            decoded = base64.b64decode(
                value.encode("ascii"), altchars=b"-_", validate=True
            )
        except Exception as exc:
            raise RuntimeError(f"enclave gateway returned invalid {field}") from exc
        if not decoded:
            raise RuntimeError(f"enclave gateway returned empty {field}")
        return decoded
