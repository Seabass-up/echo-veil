"""Keyed random-projection LSH for the durable metadata index.

The index stores only compact hyperplane signatures in SQLite and uses normal
SQLite B-tree indexes to retrieve a candidate set. Candidates are then scored
with the configured (possibly shield-aware) exact scorer. This avoids a global
row scan while keeping the implementation dependency-free and restart-stable.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import struct

import numpy as np

from .vectors import Vector, as_vector, normalize


LSH_INDEX_DERIVATION_VERSION = 2
LSH_BUCKET_TOKEN_BYTES = 32


@dataclass(frozen=True)
class LSHConfig:
    bands: int = 8
    bits_per_band: int = 8
    derivation_version: int = LSH_INDEX_DERIVATION_VERSION

    def __post_init__(self) -> None:
        if (
            isinstance(self.bands, bool)
            or isinstance(self.bits_per_band, bool)
            or not isinstance(self.bands, int)
            or not isinstance(self.bits_per_band, int)
            or self.bands <= 0
            or self.bits_per_band <= 0
        ):
            raise ValueError("LSH bands and bits_per_band must be positive")
        if self.bands > 64:
            raise ValueError("LSH bands must not exceed 64")
        if self.bits_per_band > 63:
            raise ValueError("LSH bits_per_band must not exceed 63")
        if self.derivation_version != LSH_INDEX_DERIVATION_VERSION:
            raise ValueError("LSH derivation version is unsupported")


class RandomProjectionLSH:
    """Produce profile-keyed, opaque band tokens for candidate lookup."""

    def __init__(self, index_key: bytes, config: LSHConfig | None = None) -> None:
        if not isinstance(index_key, bytes) or len(index_key) != 32:
            raise ValueError("LSH index key must contain exactly 32 bytes")
        self._index_key = index_key
        self.config = config or LSHConfig()

    @property
    def key_fingerprint(self) -> str:
        return hashlib.sha256(
            b"echo-veil-lsh-index-key-fingerprint-v2\0" + self._index_key
        ).hexdigest()

    def signatures(self, vector: Vector) -> tuple[tuple[int, bytes], ...]:
        value = normalize(as_vector(vector, allow_empty=False, name="LSH vector"))
        seed_material = hmac.new(
            self._index_key,
            b"echo-veil-lsh-projection-seed-v2\0"
            + struct.pack(">II", self.config.derivation_version, int(value.size)),
            hashlib.sha256,
        ).digest()
        seed = int.from_bytes(seed_material[:8], "big")
        rng = np.random.default_rng(seed)
        planes = rng.standard_normal(
            (self.config.bands, self.config.bits_per_band, value.size),
            dtype=np.float64,
        )
        bits = np.einsum("bij,j->bi", planes, value) >= 0.0
        signatures: list[tuple[int, bytes]] = []
        for band, band_bits in enumerate(bits):
            bucket = 0
            for offset, bit in enumerate(band_bits):
                if bool(bit):
                    bucket |= 1 << offset
            token = hmac.new(
                self._index_key,
                b"echo-veil-lsh-bucket-token-v2\0"
                + struct.pack(
                    ">IIIQ",
                    self.config.derivation_version,
                    int(value.size),
                    band,
                    bucket,
                ),
                hashlib.sha256,
            ).digest()
            if len(token) != LSH_BUCKET_TOKEN_BYTES:  # pragma: no cover
                raise RuntimeError("LSH bucket token length is invalid")
            signatures.append((band, token))
        return tuple(signatures)

    def bucket_authenticator(
        self,
        record_key: str,
        band: int,
        token: bytes,
    ) -> bytes:
        """Bind one opaque equality token to its record and band."""

        if not isinstance(record_key, str) or not record_key:
            raise ValueError("LSH record key must be non-empty")
        if isinstance(band, bool) or not isinstance(band, int) or band < 0:
            raise ValueError("LSH band must be a non-negative integer")
        if not isinstance(token, bytes) or len(token) != LSH_BUCKET_TOKEN_BYTES:
            raise ValueError("LSH bucket token is invalid")
        encoded_key = record_key.encode("utf-8", errors="strict")
        return hmac.new(
            self._index_key,
            b"echo-veil-lsh-bucket-row-auth-v2\0"
            + struct.pack(">II", len(encoded_key), band)
            + encoded_key
            + token,
            hashlib.sha256,
        ).digest()
