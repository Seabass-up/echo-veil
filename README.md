# Echo Veil

A tiered, decay-driven memory architecture for conversational agents.

Echo Veil treats an agent's working memory not as a flat store but as a managed
pool: relevant context stays "active," fading context is compressed and
eventually archived, and contradictory information is preserved as structured
tension rather than overwritten. This repository implements the core of the
Echo Veil v1.0 specification (`docs/SPEC.md`).

> **Status: 0.1.0 — core implemented, crypto layer stubbed.**
> The memory lifecycle, conflict handling, and drift detection are implemented
> and tested. The Level-5 cryptographic shield (CKKS + hardware enclave +
> zk-SNARK) is **not** implemented and is intentionally not faked. See
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
| 5. Cryptographic root shield | `crypto_shield.py` | **Interface + stub only** |
| — Facade | `oracle.py` | Implemented |

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```python
import numpy as np
from echo_veil import Oracle, WorkspaceConfig

oracle = Oracle(WorkspaceConfig(capacity=400))

# Add active memories (anchor vectors come from your embedding model).
oracle.sprout("estimate: Topping Ave", embed("200A service upgrade quote"))
oracle.sprout("family: school pickup", embed("Jaxen pickup at 3pm"))

# Each user turn: feed the current intent vector.
report = oracle.observe(embed("what was the labor rate on that estimate?"))
# -> off-topic vines drift toward twilight; on-topic ones stay active

print(oracle.report().as_dict())
```

## Run the tests

```bash
pytest -q
```

## Design notes worth knowing up front

- **The proximity-score formula is an assumption.** The source spec names the
  score but omits the equation. We define it as
  `cosine_similarity(intent, anchor) * exp(-lambda * hours_since_touched)`,
  with a tunable half-life. See `proximity.py`.
- **Compression is real, not the quoted ratio.** The spec quotes "88%
  compression"; we compress with zlib and report the *achieved* ratio.
- **The crypto shield is honest about its gap.** `NullCryptoShield` is a
  dev-only pass-through with no confidentiality; `EnclaveCryptoShield` raises
  rather than pretend. `Oracle(environment="production")` refuses to start
  without a real shield.

Full rationale, deviations, and risks: `docs/ARCHITECTURE_NOTES.md`.

## License

MIT — see `LICENSE`.
