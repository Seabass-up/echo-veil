"""Subprocess adapter for the Ristretto255 verifier binary."""

from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path

from .core import OriginConfig, ProtocolError


class RistrettoProofVerifier:
    def __init__(
        self,
        binary: str | os.PathLike[str],
        public_keys_file: str | os.PathLike[str],
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._binary = str(Path(binary).expanduser().resolve())
        self._public_keys_file = str(Path(public_keys_file).expanduser().resolve())
        if not os.path.isfile(self._binary) or not os.access(self._binary, os.X_OK):
            raise RuntimeError("Ristretto verifier binary is missing or not executable")
        if not os.path.isfile(self._public_keys_file):
            raise RuntimeError("Ristretto public-key allowlist is missing")
        if not 0.0 < timeout_seconds <= 30.0:
            raise ValueError("verifier timeout must be within (0, 30] seconds")
        self._timeout = float(timeout_seconds)

    def verify(self, proof: bytes, config: OriginConfig) -> bytes:
        request = json.dumps(
            {
                "proof_b64": base64.urlsafe_b64encode(proof).decode("ascii"),
                "provider_id": config.provider_id,
                "measurement": config.measurement,
                "key_id": config.key_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            completed = subprocess.run(  # noqa: S603 -- fixed executable, no shell
                [
                    self._binary,
                    "verify",
                    "--public-keys-file",
                    self._public_keys_file,
                ],
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._timeout,
                check=False,
                close_fds=True,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProtocolError("proof verifier unavailable") from exc
        if completed.returncode != 0 or len(completed.stdout) > 16 * 1024:
            raise ProtocolError("zero-knowledge proof rejected")
        try:
            response = json.loads(completed.stdout.decode("utf-8"))
            if response.get("valid") is not True:
                raise ValueError
            challenge = base64.b64decode(
                response["challenge_b64"].encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except Exception as exc:
            raise ProtocolError("proof verifier returned invalid output") from exc
        if not 32 <= len(challenge) <= 256:
            raise ProtocolError("proof verifier returned invalid challenge")
        return challenge
