# Integrating Echo Veil with an application agent

Echo Veil is a memory lifecycle and retrieval-policy component. It is not an
embedding model, a language model, or a complete content database. The host
agent supplies embeddings and retains the memory payload under its own access,
retention, and deletion policy. Echo Veil returns stable vine identifiers that
the host can use as payload keys.

The runnable development example is
[`examples/agent_memory.py`](../examples/agent_memory.py).

## Integration flow

For each memory worth retaining:

1. Store the authorized application payload in the host's protected content
   store.
2. Create a stable embedding using one model/version and dimension.
3. Call `Oracle.sprout(topic, embedding)` and associate the returned `vine_id`
   with the payload.

For each user turn:

1. Authorize the user before loading or embedding private content.
2. Embed the current intent with the same embedding model and dimension.
3. Call `Oracle.observe(intent)` exactly once for the turn. This advances drift,
   proximity, twilight, eviction, and persistence state.
4. Rank eligible active vines by their newly computed score. Search cold L2
   metadata with `Oracle.search_index(intent)` when the active set is
   insufficient, then resolve returned vine IDs through the authorized payload
   store.
5. Call `Oracle.check_generation_gate(score)` before giving retrieved content to
   a model. Surface `GenerationGated` to the user; never silently invent an
   answer.

Echo Veil intentionally does not call the language model. The host decides how
retrieved payloads are assembled into model context after authorization and
confidence gating.

## Minimal development adapter

```python
import numpy as np

from echo_veil import GenerationGated, Oracle

oracle = Oracle(environment="development")  # plaintext; local testing only
payloads: dict[str, str] = {}

anchor = np.array([1.0, 0.0, 0.0])  # replace with your embedding model
vine = oracle.sprout("estimate labor rate", anchor)
payloads[vine.vine_id] = "Labor rate is $125/hour."

intent = np.array([1.0, 0.0, 0.0])
oracle.observe(intent)
candidates = sorted(oracle.workspace.active(), key=lambda item: item.score, reverse=True)

if candidates:
    candidate = candidates[0]
    try:
        policy = oracle.check_generation_gate(candidate.score)
    except GenerationGated as gated:
        # Ask for clarification or explicit override as directed by gated.policy.
        print(gated.policy.indicator)
    else:
        authorized_payload = payloads[candidate.vine_id]
        print(policy.indicator, authorized_payload)
```

The example reads the exported `Workspace` collaborator to rank active vines
after `observe()`. Do not mutate returned `Vine` instances. Lifecycle mutations
must go through `Oracle.reinforce()`, `lock()`, `unlock()`, `set_crests()`, and
`forget()`.

## Security modes

| Mode | Required shield | Intended use |
|---|---|---|
| `development` / `test` | `NullCryptoShield` by default | Local tests only; no confidentiality |
| `staging` | `AesGcmCryptoShield` or reviewed staging-ready shield | Encrypted stored anchors; AES-GCM decrypts transiently for scoring |
| `local-private` | `LocalOpenFheCryptoShield` | Local native CKKS without enclave attestation |
| `production` | `EnclaveCryptoShield` | Attested CKKS, hardware isolation, and proof-gated access |

Production construction is fail-closed. Use
`build_production_enclave_shield_from_env()` only after following
[`DEPLOYMENT_RUNBOOK.md`](DEPLOYMENT_RUNBOOK.md). Cloudflare is a gateway, not
the enclave; the client must still verify fresh downstream evidence and an
approved measurement.

For staging, keep the AES key in a secret manager and reuse the same key when
reopening persisted protected vectors:

```python
from echo_veil import AesGcmCryptoShield, Oracle, SQLiteStore

shield = AesGcmCryptoShield.from_env()
store = SQLiteStore("echo-veil.db")
oracle = Oracle(environment="staging", shield=shield, storage=store)
```

Always close the store on shutdown, or use it as a context manager. Protect and
back up the database and cryptographic state together.

## Confidence behavior

- Solid and Coherent results may proceed under normal host policy.
- Fragmented results must expose gaps and inferential assembly.
- Inferential results raise `GenerationGated` until the user explicitly
  authorizes an override.
- Data Obscurity always raises `GenerationGated`; an override cannot bypass it.

An application should record the selected vine IDs, confidence policy, user
override event, and model-input provenance without logging private payloads,
secrets, raw protected vectors, proofs, or attestation credentials.

## Operational checks

- Call `oracle.capability_report().as_dict()` at startup and surface blockers in
  readiness/health reporting.
- Keep one embedding model/version and dimension per Oracle/store. Migrate to a
  new store when changing dimensions unless a reviewed migration exists.
- Treat every query as tenant-scoped. Do not share an Oracle or payload lookup
  across authorization boundaries without explicit tenant isolation.
- Call `oracle.forget(vine_id)` to remove the matching Echo Veil-managed
  L1/L2/L3 state. `SQLiteStore` performs that deletion atomically and leaves a
  live vine retryable when the transaction fails.
- Treat `forget()` as one step in the host's erasure workflow, not a complete
  erasure claim. Delete the authorized payload, tenant mapping, separately
  managed conflict/fossil artifacts, and applicable backups under host policy.
  SQLite `secure_delete` reduces ordinary page remnants, but Python memory,
  WAL files, backups, and storage media do not provide guaranteed physical
  erasure through this API.
- For user-requested erasure, revoke payload access first, enqueue an auditable
  deletion job, idempotently retry both `forget()` and host-store deletion, and
  verify every in-scope system before marking the request complete.
- Benchmark SQLite/LSH latency and recall on the real corpus. Its local durable
  behavior is not a distributed or exabyte-scale storage guarantee.
