# Echo Veil

A tiered, decay-driven memory architecture for conversational agents.

**Product site:** [echo.algo-cli.com](https://echo.algo-cli.com)

Echo Veil treats an agent's working memory not as a flat store but as a managed
pool: relevant context stays "active," fading context is compressed and
eventually archived, and contradictory information is preserved as structured
tension rather than overwritten. This repository implements the core of the
Echo Veil v1.0 specification (`docs/SPEC.md`).

> **Status: 0.6.0 — scoped protected memory with a conservative availability floor.**
> The memory lifecycle, conflict handling, drift detection, capability reporting,
> confidence-gating surfaces, and a practical AES-GCM Crypto Shield are implemented
> and tested. The repository includes an Azure SEV-SNP origin using OpenFHE CKKS,
> a Ristretto255 proof gate, Cloudflare Access/Worker configuration, and fail-closed
> attestation/session integration. Cloud credentials and hardware deployment are
> still required before these claims are active. See
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
| 5. Level-5 cryptographic root shield | `crypto_shield.py`, `echo_veil_origin`, `crates/echo-veil-zkp` | OpenFHE CKKS origin, SEV-SNP deployment, attestation, and Ristretto proof gate implemented |
| Defensive readiness / doctor report | `capability.py`, `oracle.py` | Implemented |
| — Facade | `oracle.py` | Implemented |

## Install

```bash
pip install -e ".[dev]"
```

## Agent runtime adapters

Echo Veil includes one local encrypted host adapter used across supported runtimes. It
provides five core operations—remember, recall, forget, doctor, and protected
retrieval reindexing—plus stdio maintenance operations for resumable key
rotation and explicit old-key retirement. New scoped-v2 profiles bind each
protected object to its authorization scope, record, schema, and key; encrypt
topics and retrieval vectors; use keyed opaque index terms; reconcile
interrupted writes; authenticate tombstones; and quarantine corrupt records
without serving unauthenticated content. The
bundled host configurations use the locally installed
`qwen3-embedding:latest` model through loopback-only Ollama, 1,024-dimensional
MRL output, AES-GCM protected anchors, an encrypted payload sidecar, durable
SQLite lifecycle state, and Echo Veil's confidence gate. It does not silently
capture conversations or download a model at runtime.

This is a local staging boundary. Plaintext is still visible to the authorized
process and embedding service, and Echo Veil does not automatically protect
host logs, prompts, transcripts, wiki/graph stores, backups, swap, or physical
media. The complete threat model and application entry-point contract are in
[`docs/LOCAL_AGENT_SECURITY.md`](docs/LOCAL_AGENT_SECURITY.md).

Install the model before starting a bundled adapter:

```bash
ollama pull qwen3-embedding:latest
uv run --locked python scripts/quality_benchmark.py
```

The primary quality gate qualifies 42 keyword, paraphrase, update, temporal,
and long-memory queries plus 14 unrelated and same-subject/absent-fact
distractors against a neutral synthetic corpus. Semantic recall uses a second
predicate-focused answerability gate to reject records that mention the right
subject but do not contain the requested fact. The gate also measures cold
start, restart restoration, and recall latency. It is a reproducible regression
gate, not a universal recall claim.
See [`docs/QUALITY.md`](docs/QUALITY.md) for methodology and the current
same-corpus comparison. Echo Veil stores the resolved model digest, dimension,
and query-instruction identity with each profile and refuses to mix incompatible
vectors. Because `latest` is mutable, the adapter also re-resolves that identity
before every embedding batch and stops if the artifact changes during a
long-lived process.

If the configured local Ollama service or model is unavailable, the executable
adapter can open an existing profile through an always-available read-only
layer. It uses only the encrypted keyed predicate index, requires conservative
term coverage, returns `degraded=true`, and disables remember, forget, reindex,
inferential recall, and lifecycle mutation. It never substitutes hashing
vectors or describes the result as semantic retrieval. A long-lived CLI or MCP
process makes the same one-way transition if the service becomes unavailable
during a later embedding call. Disable this path with
`--no-availability-layer` or `ECHO_VEIL_AVAILABILITY_LAYER=false`.

Agent-facing recall keeps at least two candidates so a close ranking cannot be
hidden by `top_k=1`. When `ranking_ambiguous=true`, callers must preserve both
leading records. OpenClaw responses include `host_transport.elapsed_ms` for the
fresh-process RPC boundary; this operational latency is reported separately
from the in-process semantic-recall benchmark.

Legacy hashing profiles can be rehydrated into a fresh Qwen3 profile without a
plaintext export:

```bash
uv run --locked python scripts/migrate_hashing_profile.py \
  --source-profile old-hashing --target-profile new-qwen3 --confirm
```

Codex can run the bundled stdio MCP server directly from a checkout:

```bash
codex mcp add echo-veil -- \
  uv run --project /absolute/path/to/echo-veil --locked echo-veil-agent \
    --profile codex-qwen3 --embedder ollama \
    --embedding-model qwen3-embedding:latest --embedding-dimension 1024 mcp
```

The repository root is also a Codex plugin (`.codex-plugin/plugin.json` plus
`.mcp.json`) for marketplace packaging. Native or MCP adapters are included for
OpenClaw, Hermes, Claude Code, Pi, OpenCode, Droid, and Goose. Mercury receives
a guarded Agent Skill that exposes readiness only because its documented
extension surface does not yet provide arbitrary MCP or structured custom
tools.

OpenClaw uses the native tool plugin in `integrations/openclaw`:

```bash
npm --prefix integrations/openclaw ci --ignore-scripts
npm --prefix integrations/openclaw run build
openclaw plugins install -l ./integrations/openclaw
openclaw plugins enable echo-veil
openclaw plugins doctor
```

Linked development installs auto-detect the checkout. Packaged installs can set
the plugin's `projectPath` or use an installed `echo-veil-agent` executable.
Every host uses a distinct default profile to prevent accidental cross-agent
sharing. Writable processes acquire a profile-wide lease before loading live L1
state; a second writer waits for the configured timeout and then fails closed
instead of overwriting a stale snapshot. See
[`integrations/README.md`](integrations/README.md) for the adapter
matrix and [`docs/AGENT_INTEGRATION.md`](docs/AGENT_INTEGRATION.md) for the
security and usage contract.

## Quick start

For a complete host-agent lifecycle, confidence-gating rules, security-mode
selection, and an executable adapter, see
[`docs/AGENT_INTEGRATION.md`](docs/AGENT_INTEGRATION.md).

```python
import numpy as np
from echo_veil import AesGcmCryptoShield, Oracle, SQLiteStore, WorkspaceConfig

# Development/reference mode.
_ = Oracle(WorkspaceConfig(capacity=400))

# AES-GCM is an encrypted-storage baseline for development/staging. Store its
# key in a secret manager or ECHO_VEIL_CRYPTO_KEY, not source code.
shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
store = SQLiteStore("echo-veil.db")
oracle = Oracle(
    WorkspaceConfig(capacity=400),
    shield=shield,
    environment="staging",
    storage=store,
)

# Add active memories (anchor vectors come from your embedding model).
estimate = oracle.sprout(
    "estimate: Harbor project", embed("service upgrade quote")
)
oracle.sprout("schedule: school pickup", embed("school pickup at 3pm"))

# Each user turn: feed the current intent vector.
report = oracle.observe(embed("what was the labor rate on that estimate?"))
# -> off-topic vines drift toward twilight; on-topic ones stay active

print(oracle.report().as_dict())

# Defensive readiness / production-gap report.
print(oracle.capability_report().as_dict())

# Delete Echo Veil-managed L1/L2/L3 state for one vine. The host must also
# delete its authorized payload, backups, and separately managed artifacts.
oracle.forget(estimate.vine_id)

# Checkpoint WAL state and close the database during application shutdown.
store.close()
```

### Cloudflare enclave gateway

[`cloudflare/enclave-gateway`](cloudflare/enclave-gateway) contains a deployable
Worker that validates Cloudflare Access JWTs and forwards the enclave protocol
through an mTLS binding. Configure the Python provider with the Access service
token issued for that application:

```python
from echo_veil import (
    Oracle,
    SQLiteStore,
    build_production_enclave_shield_from_env,
)

# Performs live Access authentication, fresh attestation verification,
# measurement allowlisting, Ristretto proof creation, and session opening.
shield = build_production_enclave_shield_from_env()
store = SQLiteStore("echo-veil.db")
oracle = Oracle(environment="production", shield=shield, storage=store)
```

`CloudflareEnclaveProvider.from_env()` reads the service token from
`CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET` so it does not need to
appear in application source.

The production factory additionally requires the base64 Ed25519 trust key in
`ECHO_VEIL_ATTESTATION_PUBLIC_KEY`, a JSON array in
`ECHO_VEIL_ALLOWED_MEASUREMENTS`, and the Ristretto helper/key variables
documented in the deployment runbook.

`RistrettoSchnorrProofProvider.from_env()` uses the compiled
`echo-veil-zkp` helper and an owner-only identity key. The included origin
service uses OpenFHE CKKS and consumes every proof challenge once.

The Worker is not treated as an enclave. The verifier must validate the
downstream SGX/SEV-SNP evidence and approved measurement; construction fails if
that evidence does not bind hardware isolation, CKKS similarity, and the ZKP
gate.

## Run the tests

```bash
pytest -q
```

Security issues should be reported privately through the process in
[SECURITY.md](SECURITY.md). Maintainer release controls, artifact verification,
SBOM generation, and provenance requirements are documented in
[docs/RELEASING.md](docs/RELEASING.md).

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
- **Production requires the Level-5 integration.** `Oracle(environment="production")`
  accepts `EnclaveCryptoShield` specifically; AES-GCM and custom readiness
  markers cannot bypass that guard. `EnclaveCryptoShield` requires an
  enclave provider, a deployment trust-root verifier, and a zero-knowledge proof
  provider. Construction rejects expired evidence, CKKS security below 128 bits,
  missing hardware isolation, a missing ZKP gate, or non-homomorphic similarity.
  The included Azure origin uses the official OpenFHE CKKS implementation and
  runs inside a deployment-provisioned SEV-SNP confidential VM.
- **Custom shields are conservative by default.** Echo Veil validates the
  `protect()` / `similarity()` contract. Protected payloads must implement
  `to_json_bytes()`; Echo Veil no longer falls back to archiving plaintext when
  a custom payload cannot be serialized. Capability reporting marks unknown
  custom shields degraded until their threat model is externally reviewed.
- **Inputs fail closed.** Stored vectors are copied, must be non-empty and
  finite, and must keep one embedding dimension per Oracle/Workspace. Invalid
  capacities, decay constants, timestamps, cycle overrides, confidence scores,
  and index limits are rejected at their boundaries.
- **Twilight return-to-topic recall works automatically.** A relevant intent
  now rescores and reinforces a compressed twilight vine before eviction;
  callers no longer need to know its hidden vine id in advance.
- **The adapter makes embedding selection explicit.** Bundled host profiles use
  local Qwen3 semantic embeddings with instruction-aware queries, protected
  multi-vector MaxSim over bounded live/LSH/lexical candidates, keyed lexical
  matching, topic-aware MMR, and explicit supersession history. The
  deterministic hashing backend remains available for offline tests and
  keyword-oriented recall, but is not presented as semantic retrieval. The
  Echo Veil core still accepts caller-owned stable embeddings and has no
  implicit network embedding dependency.
- **Local recall has a bounded availability floor.** A pre-existing adapter
  profile can be opened read-only when Ollama or its configured model is
  unavailable. Only strong subject-masked keyed-term matches are returned;
  every response is marked degraded, semantic/answerability claims are absent,
  and all writes and lifecycle mutation remain disabled.
- **Eviction is retry-safe.** An archive/index failure leaves an evicted vine
  pending and retriable; pruning happens only after both lower-tier writes have
  succeeded. Building the L2 entry no longer restores plaintext onto an
  externally retained evicted Vine.
- **Durable storage is available without another dependency.** `SQLiteStore`
  checkpoints active L1 vines and commits each L2 index entry, L3 archive payload, and lifecycle/topic metadata
  in one crash-recoverable transaction. It enables WAL mode, full synchronous
  durability, integrity and foreign-key checks, schema-object validation,
  cross-process writer coordination, and owner-only database-file permissions.
  The host adapter additionally reconciles lifecycle records left by an
  interrupted remember operation and refuses to delete an unexplained encrypted
  payload orphan automatically. Reopening the store restores active, twilight,
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

Echo Veil is available under the [MIT License](LICENSE). Personal, academic,
and commercial use is permitted at no charge, including modification,
distribution, sublicensing, and sale, provided the copyright and license notice
are retained. The license grants permission to use the software; it does not
transfer ownership of the original Echo Veil copyright. Third-party components
remain subject to their own licenses.
