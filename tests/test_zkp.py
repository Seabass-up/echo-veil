from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest

from echo_veil import RistrettoSchnorrProofProvider, VerifiedEnclave
from echo_veil._bounded_process import MAX_PROCESS_INPUT_BYTES, run_bounded_process


def _enclave() -> VerifiedEnclave:
    return VerifiedEnclave(
        provider_id="azure-sev-snp-eastus2",
        measurement="approved-image",
        key_id="ckks-key-1",
        expires_at=time.time() + 60,
        ckks_security_bits=128,
        hardware_isolation=True,
        zkp_access_gate=True,
        homomorphic_similarity=True,
        transport_public_key=b"k" * 32,
    )


def _helper(tmp_path: Path) -> Path:
    path = tmp_path / "proof-helper"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import base64,json,sys\n"
        "value=json.load(sys.stdin)\n"
        "assert sys.argv[1] == 'prove'\n"
        "proof=json.dumps(value,sort_keys=True).encode()\n"
        "print(json.dumps({"
        "'proof_b64':base64.urlsafe_b64encode(proof).decode(),"
        "'public_key_b64':base64.urlsafe_b64encode(b'k'*32).decode()}))\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def _key(tmp_path: Path, mode: int = 0o600) -> Path:
    path = tmp_path / "identity.key"
    path.write_text(base64.urlsafe_b64encode(b"k" * 32).decode(), encoding="ascii")
    path.chmod(mode)
    return path


def test_ristretto_provider_binds_challenge_and_attestation(tmp_path: Path) -> None:
    provider = RistrettoSchnorrProofProvider(_helper(tmp_path), _key(tmp_path))

    proof = provider.prove(b"c" * 32, _enclave())
    value = json.loads(proof)

    assert base64.urlsafe_b64decode(value["challenge_b64"]) == b"c" * 32
    assert value["provider_id"] == "azure-sev-snp-eastus2"
    assert value["measurement"] == "approved-image"
    assert value["key_id"] == "ckks-key-1"


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
def test_ristretto_provider_rejects_permissive_key_file(tmp_path: Path) -> None:
    key = _key(tmp_path, 0o644)
    assert stat.S_IMODE(key.stat().st_mode) == 0o644
    with pytest.raises(ValueError, match="group or other"):
        RistrettoSchnorrProofProvider(_helper(tmp_path), key)


def test_ristretto_provider_rejects_short_challenge(tmp_path: Path) -> None:
    provider = RistrettoSchnorrProofProvider(_helper(tmp_path), _key(tmp_path))
    with pytest.raises(ValueError, match="32..256"):
        provider.prove(b"short", _enclave())


def test_ristretto_provider_loads_paths_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ECHO_VEIL_ZKP_BINARY", str(_helper(tmp_path)))
    monkeypatch.setenv("ECHO_VEIL_ZKP_KEY_FILE", str(_key(tmp_path)))
    assert RistrettoSchnorrProofProvider.from_env() is not None


def test_ristretto_provider_bounds_helper_output(tmp_path: Path) -> None:
    helper = tmp_path / "oversized-proof-helper"
    helper.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stdout.write('x' * 20000)\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    provider = RistrettoSchnorrProofProvider(helper, _key(tmp_path))

    with pytest.raises(RuntimeError, match="safety limit"):
        provider.prove(b"c" * 32, _enclave())


def test_ristretto_provider_withholds_unrelated_host_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = tmp_path / "environment-proof-helper"
    helper.write_text(
        "#!/usr/bin/env python3\n"
        "import base64,json,os,sys\n"
        "assert 'OPENAI_API_KEY' not in os.environ\n"
        "value=json.load(sys.stdin)\n"
        "proof=json.dumps(value,sort_keys=True).encode()\n"
        "print(json.dumps({"
        "'proof_b64':base64.urlsafe_b64encode(proof).decode(),"
        "'public_key_b64':base64.urlsafe_b64encode(b'k'*32).decode()}))\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-reach-child")

    proof = RistrettoSchnorrProofProvider(helper, _key(tmp_path)).prove(
        b"c" * 32,
        _enclave(),
    )

    assert json.loads(proof)["provider_id"] == "azure-sev-snp-eastus2"


def test_bounded_process_timeout_includes_blocked_stdin_delivery(
    tmp_path: Path,
) -> None:
    helper = tmp_path / "non-reading-helper"
    helper.write_text(
        "#!/usr/bin/env python3\nimport time\ntime.sleep(5)\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    started = time.monotonic()

    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded_process(
            [str(helper)],
            input_bytes=b"x" * MAX_PROCESS_INPUT_BYTES,
            timeout_seconds=0.05,
            maximum_output_bytes=1_024,
        )

    assert time.monotonic() - started < 1.0
