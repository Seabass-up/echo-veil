# Echo Veil

A tiered, decay-driven memory architecture for conversational agents.

Echo Veil treats an agent's working memory not as a flat store but as a managed
pool: relevant context stays "active," fading context is compressed and
eventually archived, and contradictory information is preserved as structured
tension rather than overwritten. This repository implements the core of the
Echo Veil v1.0 specification (`docs/SPEC.md`).

> **Status: 0.3.0 — v1 core complete, practical Crypto Shield implemented.**
> The memory lifecycle, conflict handling, drift detection, capability reporting,
> confidence-gating surfaces, and a practical AES-GCM Crypto Shield are implemented
> and tested. The original Level-5 shield concept (CKKS + hardware enclave +
> zk-SNARK) remains a research path and is intentionally not faked. See
> `docs/ARCHITECTURE_NOTES.md`.

## What's in the box

| Spec section | Module | Status |
|---|---|---|
| 1. Tiered storage | `archive.py` (L2/L3), `workspace.py` (L1) | Implemented (in-memory reference) |
| 2. Workspace metabolism / decay loop | `workspace.py`, `proximity.py`, `vine.py` | Implemented |
| 3. Confidence spectrum matrix | `confidence.py` | Implemented |
| 3. Conflict / fossil / resurrection | `conflict.py` | Implemented |
| 4. Intent drift detection | `drift.py` | Implemented |
| 4. Caretaker / Gardener's Report | `caretaker.py` | Implemented |
| Practical Crypto Shield | `crypto_shield.py` | AES-256-GCM protected vectors implemented |
| 5. Level-5 cryptographic root shield | `crypto_shield.py` | CKKS/enclave/ZK placeholder intentionally refuses construction |
| Defensive readiness / doctor report | `capability.py`, `oracle.py` | Implemented |
| — Facade | `oracle.py` | Implemented |

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```python
import numpy as np
from echo_veil import AesGcmCryptoShield, Oracle, WorkspaceConfig

# Development/reference mode.
_ = Oracle(WorkspaceConfig(capacity=400))

# Production requires a structurally valid non-null shield. Store this key in a
# secret manager or ECHO_VEIL_CRYPTO_KEY, not source code.
shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
oracle = Oracle(WorkspaceConfig(capacity=400), shield=shield, environment="production")

# Add active memories (anchor vectors come from your embedding model).
oracle.sprout("estimate: Topping Ave", embed("200A service upgrade quote"))
oracle.sprout("family: school pickup", embed("Jaxen pickup at 3pm"))

# Each user turn: feed the current intent vector.
report = oracle.observe(embed("what was the labor rate on that estimate?"))
# -> off-topic vines drift toward twilight; on-topic ones stay active

print(oracle.report().as_dict())

# Defensive readiness / production-gap report.
print(oracle.capability_report().as_dict())
```

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
- **The Level-5 shield is honest about its gap.** `NullCryptoShield` is a
  dev-only pass-through with no confidentiality; `EnclaveCryptoShield` raises
  rather than pretend. `Oracle(environment="production")` refuses to start
  without a structurally valid shield and rejects `NullCryptoShield` explicitly.
- **Custom shields are conservative by default.** Echo Veil validates the
  `protect()` / `similarity()` contract before accepting a custom shield, but
  capability reporting marks unknown custom shields degraded until their threat
  model and protected-payload behavior are externally reviewed.
- **Capability reporting is built in.** `Oracle.capability_report()` /
  `doctor_report()` returns a JSON-serializable readiness report covering crypto,
  storage, vector index, persistence, thread safety, and confidence gating.

Full rationale, deviations, and risks: `docs/ARCHITECTURE_NOTES.md`.

## License

MIT — see `LICENSE`.
