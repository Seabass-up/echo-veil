"""FastAPI entry point for the loopback-only confidential-VM application."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .core import (
    AttestationSigner,
    EnclaveService,
    OriginConfig,
    ProtocolError,
    origin_token_matches,
)
from .openfhe_engine import OpenFheCkksEngine
from .proof_verifier import RistrettoProofVerifier

MAX_REQUEST_BYTES = 2 * 1024 * 1024


async def _read_bounded_request_body(request: Any) -> bytes:
    """Read an ASGI request without buffering past the protocol limit."""
    declared_length = request.headers.get("Content-Length")
    if declared_length is not None:
        if not declared_length.isascii() or not declared_length.isdigit():
            raise ProtocolError("invalid request size")
        if not 0 < int(declared_length) <= MAX_REQUEST_BYTES:
            raise ProtocolError("invalid request size")

    body = bytearray()
    async for chunk in request.stream():
        if not isinstance(chunk, bytes):
            raise ProtocolError("invalid request body")
        if len(chunk) > MAX_REQUEST_BYTES - len(body):
            raise ProtocolError("invalid request size")
        body.extend(chunk)
    if not body:
        raise ProtocolError("invalid request size")
    return bytes(body)


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _read_origin_token(path: str) -> str:
    token_path = Path(path)
    if not token_path.is_file():
        raise RuntimeError("origin token file is missing")
    if os.name == "posix" and token_path.stat().st_mode & 0o077:
        raise RuntimeError("origin token file permissions must be 0600 or stricter")
    token = token_path.read_text(encoding="utf-8").strip()
    if len(token) < 32:
        raise RuntimeError("origin token must contain at least 32 characters")
    return token


def build_service() -> tuple[EnclaveService, str]:
    config = OriginConfig(
        provider_id=_required_env("ECHO_VEIL_PROVIDER_ID"),
        measurement=_required_env("ECHO_VEIL_MEASUREMENT"),
        key_id=_required_env("ECHO_VEIL_CKKS_KEY_ID"),
        region=os.environ.get("ECHO_VEIL_AZURE_REGION", "eastus2"),
    )
    transport_key: X25519PrivateKey = (  # gitleaks:allow -- value is loaded at runtime
        EnclaveService.transport_key_from_secret_file(
            _required_env("ECHO_VEIL_TRANSPORT_KEY_FILE")
        )
    )
    transport_public_key = EnclaveService.transport_public_key(transport_key)
    signer = AttestationSigner.from_secret_file(
        _required_env("ECHO_VEIL_ATTESTATION_SIGNING_KEY_FILE"),
        transport_public_key,
        config,
    )
    verifier = RistrettoProofVerifier(
        _required_env("ECHO_VEIL_ZKP_BINARY"),
        _required_env("ECHO_VEIL_ALLOWED_PUBLIC_KEYS_FILE"),
    )
    ckks = OpenFheCkksEngine(
        config.key_id,
        _required_env("ECHO_VEIL_CKKS_STATE_DIRECTORY"),
        create_keys=os.environ.get("ECHO_VEIL_INITIALIZE_CKKS") == "1",
    )
    token = _read_origin_token(_required_env("ECHO_VEIL_ORIGIN_TOKEN_FILE"))
    return EnclaveService(config, transport_key, signer, verifier, ckks), token


def create_app(service: EnclaveService | None = None, origin_token: str | None = None):
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise RuntimeError("install the enclave-origin optional dependencies") from exc

    if service is None or origin_token is None:
        service, origin_token = build_service()
    application = FastAPI(
        title="Echo Veil enclave origin",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    async def decode_request(request: Request) -> dict[str, object]:
        if request.headers.get("X-Echo-Veil-mTLS") != "verified":
            raise ProtocolError("mTLS identity was not verified")
        if not origin_token_matches(origin_token, request.headers.get("Authorization")):
            raise ProtocolError("origin authentication failed")
        content_type = request.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            raise ProtocolError("application/json required")
        body = await _read_bounded_request_body(request)
        try:
            value = json.loads(body)
        except Exception as exc:
            raise ProtocolError("invalid request JSON") from exc
        if not isinstance(value, dict):
            raise ProtocolError("request must be a JSON object")
        return value

    @application.exception_handler(ProtocolError)
    async def protocol_error(_request: Request, _error: ProtocolError) -> JSONResponse:
        return JSONResponse(
            {"error": "enclave request rejected"},
            status_code=403,
            headers={"Cache-Control": "no-store"},
        )

    @application.get("/healthz")
    async def health(request: Request) -> JSONResponse:
        if request.headers.get(
            "X-Echo-Veil-mTLS"
        ) != "verified" or not origin_token_matches(
            origin_token, request.headers.get("Authorization")
        ):
            raise ProtocolError("origin authentication failed")
        return JSONResponse(service.health(), headers={"Cache-Control": "no-store"})

    @application.post("/v1/attest")
    async def attest(request: Request) -> JSONResponse:
        return JSONResponse(
            service.attest(await decode_request(request)),
            headers={"Cache-Control": "no-store"},
        )

    async def secure(path: str, request: Request) -> JSONResponse:
        return JSONResponse(
            service.process_envelope(path, await decode_request(request)),
            headers={"Cache-Control": "no-store"},
        )

    @application.post("/v1/challenge")
    async def challenge(request: Request) -> JSONResponse:
        return await secure("/v1/challenge", request)

    @application.post("/v1/session")
    async def session(request: Request) -> JSONResponse:
        return await secure("/v1/session", request)

    @application.post("/v1/vector/encrypt")
    async def encrypt_vector(request: Request) -> JSONResponse:
        return await secure("/v1/vector/encrypt", request)

    @application.post("/v1/vector/similarity")
    async def similarity(request: Request) -> JSONResponse:
        return await secure("/v1/vector/similarity", request)

    return application


def load_app() -> Any:
    """Uvicorn factory target; configuration errors prevent process startup."""
    return create_app()
