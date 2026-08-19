"""Fresh Microsoft Azure Attestation evidence from the local SKR sidecar."""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from urllib.parse import urlparse

from ._json import require_exact_keys, strict_json_loads
from .core import ProtocolError

MAX_SIDECAR_RESPONSE_BYTES = 128 * 1024
MAX_MAA_ENDPOINT_CHARS = 2_048


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        return None


class AzureMaaEvidenceProvider:
    """Request one nonce-bound MAA JWT from an owner-selected loopback sidecar."""

    def __init__(
        self,
        sidecar_url: str,
        maa_endpoint: str,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        sidecar = urlparse(sidecar_url)
        if (
            sidecar.scheme != "http"
            or sidecar.hostname not in {"127.0.0.1", "::1", "localhost"}
            or sidecar.username
            or sidecar.password
            or sidecar.query
            or sidecar.fragment
            or sidecar.path != "/attest/maa"
        ):
            raise ValueError(
                "MAA sidecar URL must be the loopback /attest/maa endpoint"
            )
        maa = urlparse(maa_endpoint)
        if (
            maa.scheme != "https"
            or not maa.hostname
            or maa.username
            or maa.password
            or maa.query
            or maa.fragment
            or len(maa_endpoint) > MAX_MAA_ENDPOINT_CHARS
        ):
            raise ValueError("MAA endpoint must be a bounded credential-free HTTPS URL")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.0 < float(timeout_seconds) <= 30.0
        ):
            raise ValueError("MAA sidecar timeout must be within (0, 30]")
        self._url = sidecar_url
        self._maa_endpoint = maa_endpoint
        self._timeout = float(timeout_seconds)
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def evidence(self, runtime_data: bytes) -> bytes:
        if not isinstance(runtime_data, bytes) or not 0 < len(runtime_data) <= 8_192:
            raise ProtocolError("native attestation runtime data is invalid")
        body = json.dumps(
            {
                "maa_endpoint": self._maa_endpoint,
                "runtime_data": base64.b64encode(runtime_data).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                declared = response.headers.get("Content-Length")
                if declared is not None and (
                    not declared.isascii()
                    or not declared.isdigit()
                    or not 0 < int(declared) <= MAX_SIDECAR_RESPONSE_BYTES
                ):
                    raise ProtocolError("native attestation response size is invalid")
                raw = response.read(MAX_SIDECAR_RESPONSE_BYTES + 1)
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            raise ProtocolError("native attestation sidecar is unavailable") from exc
        if not 0 < len(raw) <= MAX_SIDECAR_RESPONSE_BYTES:
            raise ProtocolError("native attestation response size is invalid")
        try:
            value = strict_json_loads(raw)
            if not isinstance(value, dict):
                raise ValueError
            require_exact_keys(value, {"token"})
            token = value["token"]
            if (
                not isinstance(token, str)
                or not 0 < len(token) <= 65_536
                or not token.isascii()
                or token.count(".") != 2
            ):
                raise ValueError
        except Exception as exc:
            raise ProtocolError(
                "native attestation sidecar response is invalid"
            ) from exc
        return token.encode("ascii")
