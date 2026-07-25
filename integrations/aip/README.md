# Echo Veil for AIP

AIP uses Echo Veil as its required runtime memory authority. The production
runtime constructs a fresh-process RPC adapter and passes the same backend to
its supervisor, tool registry, and provider gate. Every provider created by
`build_runtime()` is wrapped before it reaches the capability registry,
workflow engine, Agent facade, SDK, chat, or TUI. It does not create a plaintext
or RAM shadow store when Echo is unavailable: there is no plaintext fallback.

Configure the AIP runtime:

```yaml
memory:
  backend: echo_veil
  profile: echo-universal-qwen3-v1
  scope: local-user
  embedding_model: qwen3-embedding:latest
  embedding_dimension: 1024
  ollama_url: http://127.0.0.1:11434
  timeout_seconds: 120
  availability_layer: true
```

Set `memory.project_path` to an Echo Veil source checkout or
`memory.executable` to an installed `echo-veil-agent` command when automatic
sibling-checkout discovery is not appropriate. `memory.state_dir` may select a
different owner-only Echo state root. When it is omitted, AIP uses Echo Veil's
canonical user data root so `echo-universal-qwen3-v1` is the same authority used
by other same-user harnesses. Set it only for deliberate authorization-domain
or test isolation: the same profile name under a different root is a different
memory universe. These fields select execution and storage locations; they do
not weaken profile, scope, model-digest, or caller binding.

The adapter sends a bounded JSON request through stdin with `shell=False`,
inherits only an allowlisted child environment, discards child stderr, bounds
stdout, and terminates the process group on timeout. Every write adds
`caller:aip` through the Echo transport plus an authenticated AIP domain
provenance marker.

Before runtime `infer`, `stream`, or `vision` generation, AIP performs a fresh
semantic Echo preflight for the bounded current user query. The wrapper validates
the AIP/profile/query-source binding and inserts only Echo's bounded protected
context, labeled as untrusted evidence, before the underlying provider is
called. Missing, degraded, oversized, malformed, or counterfeit context blocks
the model call. Direct Agent, SDK, workflow capability, chat, streaming, and
vision routes share this single gate. Discovery, health, local embedding, and
model load/unload do not generate an agent answer and are delegated. Manually
constructed raw providers outside `build_runtime()` are outside the qualified
boundary.

AIP exposes:

- `memory.write` for explicit Live, Short-Term, or typed Contextual Logic seed
  crystals;
- `memory.refresh_live` for protected Live renewal or supersession;
- `memory.promote` for justified Live to Short-Term or Short-Term to Long-Term
  promotion;
- `memory.search` for minimal semantic recall with layer, confidence,
  provenance, ambiguity, gating, and degraded-state metadata;
- `memory.recent` for bounded, non-semantic, lifecycle-neutral inventory;
- `memory.context` for bounded authenticated Contextual Logic traces; and
- `memory.forget` for explicit erasure.

AIP searches without a domain preserve authenticated records written by other
harnesses and label their native topic with the explicit `shared` domain.
Supplying an AIP domain retains AIP's domain-specific filtering. AIP must not
discard a valid Echo result merely because another harness used a different
topic convention.

Mission `memory_policy` must be `durable` for every memory mutation. Draft-only
policy requires approval for write, refresh, or promotion. Forgetting requires
out-of-band approval unless the caller is already a trusted operator; model
output cannot approve its own erasure request. Context and bounded inventory
remain read operations.

When Ollama is unavailable, Echo may serve its encrypted keyed read-only
availability layer. AIP preserves `degraded=true` and
`semantic_available=false` on every returned entry. Echo blocks writes and
lifecycle mutation in this mode; AIP does not substitute keyword hashing or
plaintext storage.

Legacy AIP markdown memory is retained only as a test/migration reader. Rehydrate
it explicitly from the AIP checkout; dry-run is the default:

```bash
PYTHONPATH=src python scripts/migrate_markdown_memory_to_echo.py \
  --source /path/to/legacy/memories

PYTHONPATH=src python scripts/migrate_markdown_memory_to_echo.py \
  --source /path/to/legacy/memories \
  --confirm
```

The migration never deletes or modifies the source. Keep it until a fresh
process, protected inventory, semantic recall, and application-level retention
review have all passed. It targets the canonical shared user authority by
default; `--state-dir` is reserved for a deliberately isolated target.

The installed AIP boundary is qualified only when both fixed probes pass:

```bash
aip --version
aip authority-receipt
```

The receipt is payload- and path-silent. It must bind version `0.1.1` to the
reviewed wheel SHA-256 through PEP 610 metadata and verify every installed AIP
Python source file against the wheel `RECORD`. Editable, unhashed, incomplete,
modified, or permissively writable installations fail closed. Echo's
`verify_host_authority.py --installed --require-current aip` compares that
receipt with the exact artifact digest recorded in the authority manifest.

Local AES-GCM profiles are staging-grade protection, not proof of a live
attested enclave. AIP must continue to report `production_ready=false` until
the external CKKS, hardware-attestation, ZKP, Access, mTLS, and operational
controls are independently provisioned and verified.
