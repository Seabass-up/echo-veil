"""OpenFHE CKKS engine used inside the Azure confidential VM.

OpenFHE is imported lazily because its official wheels target Ubuntu LTS rather
than every platform supported by the Echo Veil client library.
"""

from __future__ import annotations

import base64
import json
import math
import threading
from collections.abc import Sequence
from pathlib import Path


class OpenFheCkksEngine:
    """Normalize in the enclave, encrypt with CKKS, and decrypt only the dot sum."""

    def __init__(
        self,
        key_id: str,
        state_directory: str | Path,
        *,
        batch_size: int = 16_384,
        create_keys: bool = False,
    ) -> None:
        if not key_id:
            raise ValueError("CKKS key ID is required")
        if batch_size <= 0 or batch_size & (batch_size - 1):
            raise ValueError("CKKS batch size must be a positive power of two")
        try:
            import openfhe  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError(
                "the official OpenFHE Python package is required on the enclave origin"
            ) from exc
        self._openfhe = openfhe
        self.key_id = key_id
        self._batch_size = batch_size
        self._directory = Path(state_directory)
        self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock = threading.RLock()
        if (self._directory / "context.bin").exists():
            self._load()
        elif create_keys:
            self._create()
        else:
            raise RuntimeError(
                "CKKS key state is missing; run the one-time enclave key initializer"
            )

    def _create(self) -> None:
        fhe = self._openfhe
        parameters = fhe.CCParamsCKKSRNS()
        parameters.SetMultiplicativeDepth(2)
        parameters.SetScalingModSize(50)
        parameters.SetBatchSize(self._batch_size)
        parameters.SetSecurityLevel(fhe.SecurityLevel.HEStd_128_classic)
        self._context = fhe.GenCryptoContext(parameters)
        self._context.Enable(fhe.PKESchemeFeature.PKE)
        self._context.Enable(fhe.PKESchemeFeature.KEYSWITCH)
        self._context.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
        self._context.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)
        keys = self._context.KeyGen()
        self._public_key = keys.publicKey
        self._secret_key = keys.secretKey
        self._context.EvalSumKeyGen(self._secret_key)
        self._serialize_state()

    def _serialize_state(self) -> None:
        fhe = self._openfhe
        files = {
            "context.bin": (self._context, fhe.BINARY),
            "public-key.bin": (self._public_key, fhe.BINARY),
            "secret-key.bin": (self._secret_key, fhe.BINARY),
        }
        for filename, (value, kind) in files.items():
            path = self._directory / filename
            if not fhe.SerializeToFile(str(path), value, kind):
                raise RuntimeError(f"could not serialize CKKS {filename}")
            path.chmod(0o600)
        eval_path = self._directory / "eval-sum.bin"
        if not self._context.SerializeEvalAutomorphismKey(str(eval_path), fhe.BINARY):
            raise RuntimeError("could not serialize CKKS summation keys")
        eval_path.chmod(0o600)

    def _load(self) -> None:
        fhe = self._openfhe
        self._context, context_ok = fhe.DeserializeCryptoContext(
            str(self._directory / "context.bin"), fhe.BINARY
        )
        self._public_key, public_ok = fhe.DeserializePublicKey(
            str(self._directory / "public-key.bin"), fhe.BINARY
        )
        self._secret_key, secret_ok = fhe.DeserializePrivateKey(
            str(self._directory / "secret-key.bin"), fhe.BINARY
        )
        eval_ok = self._context.DeserializeEvalAutomorphismKey(
            str(self._directory / "eval-sum.bin"), fhe.BINARY
        )
        if not all((context_ok, public_ok, secret_ok, eval_ok)):
            raise RuntimeError("CKKS key state could not be loaded")

    def encrypt_normalized(self, vector: Sequence[float]) -> bytes:
        if not 0 < len(vector) <= self._batch_size:
            raise ValueError("vector exceeds CKKS batch size")
        with self._lock:
            plaintext = self._context.MakeCKKSPackedPlaintext(list(vector))
            ciphertext = self._context.Encrypt(self._public_key, plaintext)
            serialized = bytes(
                self._openfhe.Serialize(ciphertext, self._openfhe.BINARY)
            )
        return json.dumps(
            {
                "format": "openfhe-ckks-v1",
                "dimension": len(vector),
                "ciphertext_b64": base64.urlsafe_b64encode(serialized).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _decode(self, ciphertext: bytes) -> tuple[int, object]:
        try:
            value = json.loads(ciphertext.decode("utf-8"))
            if value.get("format") != "openfhe-ckks-v1":
                raise ValueError
            dimension = int(value["dimension"])
            raw = base64.b64decode(
                value["ciphertext_b64"].encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
            decoded = self._openfhe.DeserializeCiphertextString(
                raw, self._openfhe.BINARY
            )
        except Exception as exc:
            raise ValueError("invalid OpenFHE CKKS ciphertext") from exc
        if not 0 < dimension <= self._batch_size:
            raise ValueError("invalid OpenFHE CKKS dimension")
        return dimension, decoded

    def ciphertext_dimension(self, ciphertext: bytes) -> int:
        dimension, _ = self._decode(ciphertext)
        return dimension

    def cosine_similarity(
        self, normalized_intent: Sequence[float], ciphertext: bytes
    ) -> float:
        dimension, encrypted_anchor = self._decode(ciphertext)
        if len(normalized_intent) != dimension:
            raise ValueError("CKKS vector dimension mismatch")
        with self._lock:
            encoded_intent = self._context.MakeCKKSPackedPlaintext(
                list(normalized_intent)
            )
            products = self._context.EvalMult(encrypted_anchor, encoded_intent)
            summed = self._context.EvalSum(products, dimension)
            result = self._context.Decrypt(summed, self._secret_key)
            result.SetLength(1)
            score = float(result.GetRealPackedValue()[0])
        if not math.isfinite(score):
            raise RuntimeError("OpenFHE produced a non-finite CKKS result")
        return score
