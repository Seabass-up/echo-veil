"""Subprocess adapter for the Ristretto255 verifier binary."""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
from pathlib import Path

from echo_veil._bounded_process import (
    ProcessOutputLimitError,
    run_bounded_process,
)

from ._json import require_exact_keys, strict_json_loads
from .core import OriginConfig, ProtocolError, VerifiedProof


class RistrettoProofVerifier:
    def __init__(
        self,
        binary: str | os.PathLike[str],
        public_keys_file: str | os.PathLike[str],
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        binary_path = Path(binary).expanduser().absolute()
        public_keys_path = Path(public_keys_file).expanduser().absolute()
        if any(
            component.is_symlink()
            for path in (binary_path, public_keys_path)
            for component in (path, *path.parents)
        ):
            raise RuntimeError("Ristretto verifier paths must not be symbolic links")
        self._binary = str(binary_path.resolve())
        self._public_keys_file = str(public_keys_path.resolve())
        if not os.path.isfile(self._binary) or not os.access(self._binary, os.X_OK):
            raise RuntimeError("Ristretto verifier binary is missing or not executable")
        if not os.path.isfile(self._public_keys_file):
            raise RuntimeError("Ristretto public-key allowlist is missing")
        if os.name == "posix":
            binary_mode = stat.S_IMODE(os.stat(self._binary).st_mode)
            allowlist_mode = stat.S_IMODE(os.stat(self._public_keys_file).st_mode)
            if binary_mode & 0o022:
                raise RuntimeError(
                    "Ristretto verifier binary must not be group/world writable"
                )
            if allowlist_mode & 0o022:
                raise RuntimeError(
                    "Ristretto public-key allowlist must not be group/world writable"
                )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.0 < float(timeout_seconds) <= 30.0
        ):
            raise ValueError("verifier timeout must be within (0, 30] seconds")
        self._timeout = float(timeout_seconds)

    def verify(self, proof: bytes, config: OriginConfig) -> VerifiedProof:
        if not isinstance(proof, bytes) or not 0 < len(proof) <= 4_096:
            raise ProtocolError("zero-knowledge proof rejected")
        if not isinstance(config, OriginConfig):
            raise ProtocolError("proof verifier configuration is invalid")
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
            completed = run_bounded_process(
                [
                    self._binary,
                    "verify",
                    "--public-keys-file",
                    self._public_keys_file,
                ],
                input_bytes=request,
                timeout_seconds=self._timeout,
                maximum_output_bytes=16 * 1024,
            )
        except (OSError, subprocess.TimeoutExpired, ProcessOutputLimitError) as exc:
            raise ProtocolError("proof verifier unavailable") from exc
        if completed.returncode != 0:
            raise ProtocolError("zero-knowledge proof rejected")
        try:
            response = strict_json_loads(completed.stdout)
            if not isinstance(response, dict):
                raise ValueError
            require_exact_keys(
                response,
                {"valid", "challenge_b64", "public_key_b64"},
            )
            encoded_challenge = response["challenge_b64"]
            encoded_public_key = response["public_key_b64"]
            if (
                response.get("valid") is not True
                or not isinstance(encoded_challenge, str)
                or not isinstance(encoded_public_key, str)
            ):
                raise ValueError
            challenge = base64.b64decode(
                encoded_challenge.encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
            public_key = base64.b64decode(
                encoded_public_key.encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
            if (
                base64.urlsafe_b64encode(challenge).decode("ascii") != encoded_challenge
                or base64.urlsafe_b64encode(public_key).decode("ascii")
                != encoded_public_key
                or len(public_key) != 32
            ):
                raise ValueError
        except Exception as exc:
            raise ProtocolError("proof verifier returned invalid output") from exc
        if not 32 <= len(challenge) <= 256:
            raise ProtocolError("proof verifier returned invalid challenge")
        return VerifiedProof(challenge=challenge, public_key=public_key)
