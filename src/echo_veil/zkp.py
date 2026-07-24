"""Deployment adapter for the audited Ristretto255 proof helper.

The curve implementation lives in ``crates/echo-veil-zkp``. Keeping the secret
scalar in an owner-only file and invoking the helper without a shell avoids
placing key material in Python objects, environment variables, or process
arguments.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

from ._bounded_process import ProcessOutputLimitError, run_bounded_process
from ._json import require_exact_keys, strict_json_loads
from .crypto_shield import VerifiedEnclave

DEFAULT_ZKP_BINARY_ENV = "ECHO_VEIL_ZKP_BINARY"
DEFAULT_ZKP_KEY_FILE_ENV = "ECHO_VEIL_ZKP_KEY_FILE"
MAX_PROOF_BYTES = 4096
MAX_HELPER_OUTPUT_BYTES = 16 * 1024


class RistrettoSchnorrProofProvider:
    """Create challenge- and attestation-bound Schnorr possession proofs."""

    def __init__(
        self,
        binary: str | os.PathLike[str],
        key_file: str | os.PathLike[str],
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        raw_binary = os.fspath(binary)
        resolved_binary = (
            shutil.which(raw_binary)
            if os.path.sep not in raw_binary
            else str(Path(raw_binary).expanduser().resolve())
        )
        if not resolved_binary or not os.path.isfile(resolved_binary):
            raise ValueError("Ristretto proof helper binary was not found")
        if not os.access(resolved_binary, os.X_OK):
            raise ValueError("Ristretto proof helper binary is not executable")
        if (
            os.name == "posix"
            and stat.S_IMODE(os.stat(resolved_binary).st_mode) & 0o022
        ):
            raise ValueError(
                "Ristretto proof helper binary must not be group/world writable"
            )
        supplied_key = Path(key_file).expanduser().absolute()
        if any(
            component.is_symlink()
            for component in (supplied_key, *supplied_key.parents)
        ):
            raise ValueError(
                "Ristretto identity key path must not contain symbolic links"
            )
        resolved_key = supplied_key.resolve()
        if not resolved_key.is_file():
            raise ValueError("Ristretto identity key file was not found")
        if os.name == "posix":
            mode = stat.S_IMODE(resolved_key.stat().st_mode)
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ValueError(
                    "Ristretto identity key file must not be accessible by group or other"
                )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.0 < float(timeout_seconds) <= 30.0
        ):
            raise ValueError("proof helper timeout must be within (0, 30] seconds")
        self._binary = resolved_binary
        self._key_file = str(resolved_key)
        self._timeout = float(timeout_seconds)

    @classmethod
    def from_env(
        cls,
        *,
        binary_env: str = DEFAULT_ZKP_BINARY_ENV,
        key_file_env: str = DEFAULT_ZKP_KEY_FILE_ENV,
        timeout_seconds: float = 5.0,
    ) -> RistrettoSchnorrProofProvider:
        binary = os.environ.get(binary_env, "")
        key_file = os.environ.get(key_file_env, "")
        if (
            not binary
            or binary != binary.strip()
            or not key_file
            or key_file != key_file.strip()
        ):
            raise ValueError(f"{binary_env} and {key_file_env} must both be set")
        return cls(binary, key_file, timeout_seconds=timeout_seconds)

    def prove(self, challenge: bytes, enclave: VerifiedEnclave) -> bytes:
        if not isinstance(challenge, bytes) or not 32 <= len(challenge) <= 256:
            raise ValueError("enclave challenge must contain 32..256 bytes")
        if not isinstance(enclave, VerifiedEnclave):
            raise TypeError("enclave must be a VerifiedEnclave")
        request = json.dumps(
            {
                "challenge_b64": base64.urlsafe_b64encode(challenge).decode("ascii"),
                "provider_id": enclave.provider_id,
                "measurement": enclave.measurement,
                "key_id": enclave.key_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            completed = run_bounded_process(
                [self._binary, "prove", "--key-file", self._key_file],
                input_bytes=request,
                timeout_seconds=self._timeout,
                maximum_output_bytes=MAX_HELPER_OUTPUT_BYTES,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Ristretto proof helper timed out") from exc
        except ProcessOutputLimitError as exc:
            raise RuntimeError(
                "Ristretto proof helper output exceeded the safety limit"
            ) from exc
        except OSError as exc:
            raise RuntimeError("Ristretto proof helper could not be executed") from exc
        if completed.returncode != 0:
            raise RuntimeError("Ristretto proof helper rejected the request")
        try:
            response = strict_json_loads(completed.stdout)
            if not isinstance(response, dict):
                raise TypeError
            require_exact_keys(response, {"proof_b64", "public_key_b64"})
            encoded = response["proof_b64"]
            encoded_public_key = response["public_key_b64"]
            if not isinstance(encoded, str) or not isinstance(encoded_public_key, str):
                raise TypeError
            proof = base64.b64decode(
                encoded.encode("ascii"), altchars=b"-_", validate=True
            )
            public_key = base64.b64decode(
                encoded_public_key.encode("ascii"), altchars=b"-_", validate=True
            )
            if (
                base64.urlsafe_b64encode(proof).decode("ascii") != encoded
                or base64.urlsafe_b64encode(public_key).decode("ascii")
                != encoded_public_key
                or len(public_key) != 32
            ):
                raise ValueError
        except Exception as exc:
            raise RuntimeError(
                "Ristretto proof helper returned invalid output"
            ) from exc
        if not 0 < len(proof) <= MAX_PROOF_BYTES:
            raise RuntimeError("Ristretto proof helper returned an invalid proof size")
        return proof
