# Integrating Echo Veil with an application agent

Echo Veil is a memory lifecycle and retrieval-policy component. It is not an
embedding model, a language model, or a complete content database. The host
agent supplies embeddings and retains the memory payload under its own access,
retention, and deletion policy. Echo Veil returns stable vine identifiers that
the host can use as payload keys.

The runnable development example is
[`examples/agent_memory.py`](../examples/agent_memory.py).

## Ready-to-run agent adapters

`echo_veil.agent_memory.AgentMemory` implements the host responsibilities for a
single local OS user. It creates an owner-only profile directory, protects
vectors with AES-GCM, encrypts authorized payloads in a separate SQLite
database, and performs confidence-gated active/cold recall. Exact remember
retries are deduplicated. Topics remain plaintext metadata and the local mode
does not satisfy the production enclave profile.

The bundled full adapters explicitly select `qwen3-embedding:latest` through a
loopback-only Ollama client. Documents are embedded without a prefix; recall
queries use Qwen3's retrieval-instruction format. The default output dimension
is 1,024 and the calibrated minimum recall score is `0.50`. The adapter never
auto-pulls a model, follows redirects, contacts a non-loopback origin, or falls
back silently to hashing.

```bash
ollama pull qwen3-embedding:latest
uv run --locked python scripts/quality_benchmark.py
```

Qwen3 supports instruction-aware retrieval and Matryoshka Representation
Learning dimensions; see the
[official model card](https://huggingface.co/Qwen/Qwen3-Embedding-8B) and
[Ollama embed API](https://docs.ollama.com/api/embed). Model quality, footprint,
and latency remain deployment tradeoffs, so qualify the real corpus before
making a profile primary.

The console entry point accepts payload-bearing requests only through stdin:

```bash
printf '%s' '{"action":"doctor","arguments":{}}' | echo-veil-agent rpc
echo-veil-agent mcp
```

Codex consumes `mcp` over stdio. The checked-in `.mcp.json` uses
`uv run --locked echo-veil-agent mcp` when the repository is installed as a
Codex plugin. For a direct local setup:

```bash
codex mcp add echo-veil -- \
  uv run --project /absolute/path/to/echo-veil --locked echo-veil-agent \
    --profile codex-qwen3 --embedder ollama \
    --embedding-model qwen3-embedding:latest --embedding-dimension 1024 mcp
```

OpenClaw loads `integrations/openclaw` as a native tool plugin. Pi loads a
native TypeScript extension package. Codex and Claude Code use plugin-bundled
stdio MCP servers. Hermes, OpenCode, Droid, and Goose use their documented
stdio MCP configuration surfaces. Every full adapter exposes:

- `echo_veil_remember` — opt-in durable capture;
- `echo_veil_recall` — lifecycle-mutating, confidence-gated retrieval;
- `echo_veil_forget` — payload-first local erasure;
- `echo_veil_doctor` — adapter and core readiness reporting; and
- `echo_veil_reindex` — explicitly confirmed protected retrieval-index rebuilds.

Existing host memory providers and context engines remain unchanged. Echo Veil
is not injected into every prompt and does not replace host-native memory. This
avoids duplicate automatic recall while the policy layer is evaluated.

`ECHO_VEIL_STATE_DIR` and `ECHO_VEIL_PROFILE` select storage. The embedding
backend is selected with `ECHO_VEIL_EMBEDDER`; Ollama model, dimension, URL, and
timeout use the corresponding `ECHO_VEIL_EMBEDDING_*` and
`ECHO_VEIL_OLLAMA_URL` variables. Bundled adapters use a versioned Qwen3 profile
per host. Profiles are authorization and concurrency
boundaries: share one only when the hosts represent the same local user and
authorization domain, and avoid simultaneous writers because live L1 remains
process memory even though SQLite persistence is cross-process safe.

Embedding identity is immutable for a non-empty profile. To move a hashing
profile to Qwen3, use the explicit in-process migration below. It decrypts one
source record at a time, re-embeds it into an empty target profile, preserves
explicit supersession links, and creates no plaintext export file. It does not
modify the source profile. It creates new vine IDs and fresh lifecycle state;
scores, reinforcement age, locks, and archive position are not copied.

```bash
uv run --locked python scripts/migrate_hashing_profile.py \
  --source-profile old-hashing --target-profile new-qwen3 --confirm
```

Do not copy or mix old vectors. If the resolved `latest` tag digest changes,
review the model change and migrate to a new profile instead of weakening the
mismatch check.

The bundled adapter's retrieval path uses encrypted passage vectors with
MaxSim, keyed-hash lexical features, topic-aware MMR diversity, and explicit
`effective_at`/`supersedes` metadata. `recall(as_of=...)` can select the fact
valid at a historical point without discarding later corrections. Run
`echo_veil_reindex` after upgrading an existing profile so its derived protected
retrieval data matches the current schema.

Mercury is intentionally readiness-only. Its current public documentation
supports Agent Skills but not arbitrary MCP or structured custom-tool
registration. Sending protected content through shell arguments, pipelines,
temporary files, URLs, or environment variables would create plaintext traces,
so the included Mercury skill refuses remember, recall, and forget until the
host exposes a reviewed structured boundary. See
[`integrations/README.md`](../integrations/README.md) for install and validation
commands for every host.

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
   proximity, twilight, eviction, and persistence state. A returning relevant
   intent also rescores and automatically reinforces a twilight vine before it
   expires.
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
payloads[vine.vine_id] = "Synthetic example labor rate is $137/hour."

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
  new profile when changing dimensions or model identity; use only the reviewed
  hashing-to-Qwen migration above for legacy adapter profiles.
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
