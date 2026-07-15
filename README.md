# Echo Veil

A tiered, decay-driven memory architecture for conversational agents.

Echo Veil treats an agent's working memory not as a flat store but as a managed
pool: relevant context stays "active," fading context is compressed and
eventually archived, and contradictory information is preserved as structured
tension rather than overwritten. This repository implements the core of the
Echo Veil v1.0 specification (`docs/SPEC.md`).

> **Status: 0.4.0 — durable active memory, indexed retrieval, and attested confidential-compute integration.**
> The memory lifecycle, conflict handling, drift detection, capability reporting,
> confidence-gating surfaces, and a practical AES-GCM Crypto Shield are implemented
> and tested. Production deployments can connect a CKKS enclave provider through
> a fail-closed attestation and zero-knowledge access-proof boundary. See
> `docs/ARCHITECTURE_NOTES.md`.

## What's in the box

| Spec section | Module | Status |
|---|---|---|
| 1. Tiered storage | `archive.py`, `persistence.py`, `workspace.py` | In-memory reference + durable transactional SQLite L1/L2/L3 |
| 2. Workspace metabolism / decay loop | `workspace.py`, `proximity.py`, `vine.py` | Implemented |
| 3. Confidence spectrum matrix | `confidence.py` | Implemented |
| 3. Conflict / fossil / resurrection | `conflict.py` | Implemented |
| 4. Intent drift detection | `drift.py` | Implemented |
| 4. Caretaker / Gardener's Report | `caretaker.py` | Implemented |
| Practical Crypto Shield | `crypto_shield.py` | AES-256-GCM protected vectors implemented |
| 5. Level-5 cryptographic root shield | `crypto_shield.py` | Attested CKKS enclave and ZKP provider adapter implemented |
| Defensive readiness / doctor report | `capability.py`, `oracle.py` | Implemented |
| — Facade | `oracle.py` | Implemented |

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```python
import numpy as np
from echo_veil import AesGcmCryptoShield, Oracle, SQLiteStore, WorkspaceConfig

# Development/reference mode.
_ = Oracle(WorkspaceConfig(capacity=400))

# Production/staging requires a shield that explicitly declares production
# readiness. AesGcmCryptoShield does; store its key in a secret manager or
# ECHO_VEIL_CRYPTO_KEY, not source code.
shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
store = SQLiteStore("echo-veil.db")
oracle = Oracle(
    WorkspaceConfig(capacity=400),
    shield=shield,
    environment="production",
    storage=store,
)

# Add active memories (anchor vectors come from your embedding model).
oracle.sprout("estimate: Topping Ave", embed("200A service upgrade quote"))
oracle.sprout("family: school pickup", embed("Jaxen pickup at 3pm"))

# Each user turn: feed the current intent vector.
report = oracle.observe(embed("what was the labor rate on that estimate?"))
# -> off-topic vines drift toward twilight; on-topic ones stay active

print(oracle.report().as_dict())

# Defensive readiness / production-gap report.
print(oracle.capability_report().as_dict())

# Checkpoint WAL state and close the database during application shutdown.
store.close()
```

### Cloudflare enclave gateway

[`cloudflare/enclave-gateway`](cloudflare/enclave-gateway) contains a deployable
Worker that validates Cloudflare Access JWTs and forwards the enclave protocol
through an mTLS binding. Configure the Python provider with the Access service
token issued for that application:

```python
from echo_veil import CloudflareEnclaveProvider, EnclaveCryptoShield

provider = CloudflareEnclaveProvider(
    "https://memory.example.com",
    access_client_id,
    access_client_secret,
)
shield = EnclaveCryptoShield(provider, vendor_attestation_verifier, zkp_prover)
```

`CloudflareEnclaveProvider.from_env()` reads the service token from
`CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET` so it does not need to
appear in application source.

The Worker is not treated as an enclave. The verifier must validate the
downstream SGX/SEV-SNP evidence and approved measurement; construction fails if
that evidence does not bind hardware isolation, CKKS similarity, and the ZKP
gate.

## Run the tests

```bash
pytest -q
```

## Design notes worth knowing up front

- **The proximity-score formula is an assumption.** The preserved source spec
  names the score but omits its equation block. This implementation uses
  `cosine_similarity(intent, anchor) + 0.15 * exp(-hours_since_touched / 12)`,
  with a tunable time constant. See `proximity.py`.
- **Compression is real, not the quoted ratio.** The spec quotes "88%
  compression"; we compress with zlib and report the *achieved* ratio.
- **The practical crypto shield is real but scoped.** `AesGcmCryptoShield`
  encrypts and authenticates protected vectors with AES-256-GCM and decrypts
  transiently during `similarity()`. It is suitable for practical encrypted
  vector storage, but it is not homomorphic and not an enclave.
- **The Level-5 integration fails closed.** `EnclaveCryptoShield` requires an
  enclave provider, a deployment trust-root verifier, and a zero-knowledge proof
  provider. Construction rejects expired evidence, CKKS security below 128 bits,
  missing hardware isolation, a missing ZKP gate, or non-homomorphic similarity.
  Echo Veil does not emulate SGX/SEV-SNP or roll its own CKKS in Python; the
  configured provider supplies those deployment-specific primitives.
- **Custom shields are conservative by default.** Echo Veil validates the
  `protect()` / `similarity()` contract. Protected payloads must implement
  `to_json_bytes()`; Echo Veil no longer falls back to archiving plaintext when
  a custom payload cannot be serialized. Capability reporting marks unknown
  custom shields degraded until their threat model is externally reviewed.
- **Inputs fail closed.** Stored vectors are copied, must be non-empty and
  finite, and must keep one embedding dimension per Oracle/Workspace. Invalid
  capacities, decay constants, timestamps, cycle overrides, confidence scores,
  and index limits are rejected at their boundaries.
- **Eviction is retry-safe.** An archive/index failure leaves an evicted vine
  pending and retriable; pruning happens only after both lower-tier writes have
  succeeded. Building the L2 entry no longer restores plaintext onto an
  externally retained evicted Vine.
- **Durable storage is available without another dependency.** `SQLiteStore`
  checkpoints active L1 vines and commits each L2 index entry, L3 archive payload, and lifecycle/topic metadata
  in one crash-recoverable transaction. It enables WAL mode, full synchronous
  durability, integrity checks, cross-process writer coordination, and owner-only
  database-file permissions. Reopening the store restores active, twilight,
  locked, and focal-crest state as well as searchable lower-tier memory.
- **SQLite retrieval is indexed.** Stable random-projection LSH signatures are
  stored in indexed SQLite buckets. Lookup selects approximate cosine-neighbor
  candidates and then applies the exact shield-aware scorer. Schema-v1 databases
  migrate automatically and backfill signatures for plaintext entries.
- **Internal operations are serialized.** Oracle, Workspace, index, archive,
  and drift mutations use reentrant locks. Returned `Vine` objects remain
  mutable, so callers should not edit them concurrently or bypass the public
  mutation methods.
- **Capability reporting is built in.** `Oracle.capability_report()` /
  `doctor_report()` returns a JSON-serializable readiness report covering crypto,
  storage, vector index, persistence, thread safety, and confidence gating.

Full rationale, deviations, and risks: `docs/ARCHITECTURE_NOTES.md`.

## License

MIT — see `LICENSE`.
