# Agent runtime adapters

Echo Veil exposes one bounded local tool contract to every supported host:
`echo_veil_remember`, `echo_veil_recall`, `echo_veil_forget`,
`echo_veil_doctor`, and explicitly confirmed `echo_veil_reindex`. Remember and
forget are always explicit operations. Recall
advances the memory lifecycle and can return confidence-gated metadata without
revealing a payload.

If local Ollama or the configured model is unavailable, every full adapter can
use the same existing profile through an explicitly degraded read-only layer.
It returns only strong encrypted keyed-term matches, marks
`semantic_available=false`, and disables remember, forget, reindex,
inferential recall, and lifecycle mutation until semantic service is restored.
These results are lexical availability hints, not semantic or authoritative
recall. Full callers preserve both leading candidates whenever
`ranking_ambiguous=true`; the common RPC/MCP boundary enforces at least two
recall slots for legacy callers.

Install the Python command before using a standalone host configuration:

```bash
uv tool install --from /absolute/path/to/echo-veil echo-veil
ollama pull qwen3-embedding:latest
echo-veil-agent --profile smoke-test-qwen3 --embedder ollama \
  --embedding-model qwen3-embedding:latest --embedding-dimension 1024 doctor
```

For checkout development, the Codex and Claude Code bundles run the locked
project directly. The OpenClaw and Pi adapters also auto-detect the checkout
when loaded from this repository.

| Host | Adapter | Install or validate |
| --- | --- | --- |
| OpenClaw | Native tool plugin | `openclaw plugins install -l ./integrations/openclaw` |
| Hermes | stdio MCP config | Copy `integrations/hermes/config.yaml` into `~/.hermes/config.yaml`, then `hermes mcp test echo-veil` |
| Codex | Codex plugin + stdio MCP | Use the repository plugin, or run `codex mcp add echo-veil -- echo-veil-agent --profile codex mcp` |
| Claude Code | Claude plugin + stdio MCP | `claude plugin validate ./integrations/claude-code` |
| Pi | Native TypeScript extension package | `pi install ./integrations/pi` |
| OpenCode | Local MCP config | Merge `integrations/opencode/opencode.json` into your config, then `opencode mcp list` |
| Droid | Project MCP config | Copy `integrations/droid/.factory` into the target project, then `droid mcp list` |
| Goose | Portable recipe with stdio extension | `goose recipe validate integrations/goose/echo-veil.yaml` |
| Mercury | Guarded Agent Skill | Install `integrations/mercury/SKILL.md`; see its explicit host limitation |

Each full adapter defaults to a versioned, host-specific Qwen3 profile. This is
intentional: profiles are embedding-identity, authorization, and concurrency
boundaries. Set the same profile only when
the hosts represent the same local user and authorization domain, and do not
run simultaneous writers against a shared live-L1 profile. SQLite safely
persists checkpoints and lower tiers, but live L1 remains process memory.

The full adapters use `qwen3-embedding:latest` through loopback-only Ollama with
1,024-dimensional output and instruction-aware recall queries. The model is not
downloaded automatically. The deterministic hashing backend remains an
explicit test/legacy keyword backend; it is not the outage layer. The outage
layer reads the existing keyed index and never substitutes incompatible
vectors. None of these modes is the production CKKS/enclave/ZKP profile,
silently captures conversations, or replaces a host's payload authorization
policy.

Run `uv run --locked python scripts/quality_benchmark.py` before primary use,
then benchmark the real authorized corpus. Existing hashing profiles must stay
on hashing or use `scripts/migrate_hashing_profile.py` to re-embed into an empty
Qwen3 profile without a plaintext export; incompatible embedding identities
fail closed.
