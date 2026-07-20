# Agent runtime adapters

Echo Veil exposes one bounded local tool contract to every supported host:
`echo_veil_remember`, `echo_veil_recall`, `echo_veil_forget`, and
`echo_veil_doctor`. Remember and forget are always explicit operations. Recall
advances the memory lifecycle and can return confidence-gated metadata without
revealing a payload.

Install the Python command before using a standalone host configuration:

```bash
uv tool install --from /absolute/path/to/echo-veil echo-veil
echo-veil-agent --profile smoke-test doctor
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

Each adapter defaults to a host-specific profile. This is intentional: profiles
are authorization and concurrency boundaries. Set the same profile only when
the hosts represent the same local user and authorization domain, and do not
run simultaneous writers against a shared live-L1 profile. SQLite safely
persists checkpoints and lower tiers, but live L1 remains process memory.

The local adapter uses AES-GCM staging protection and a deterministic
keyword-oriented embedder. It is not the production CKKS/enclave/ZKP profile,
does not silently capture conversations, and does not replace a host's payload
authorization policy.
