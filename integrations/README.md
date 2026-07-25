# Agent runtime adapters

Echo Veil exposes one bounded local tool contract to every supported host:
`echo_veil_remember`, `echo_veil_refresh_live`, `echo_veil_promote`,
`echo_veil_recall`, `echo_veil_context`, `echo_veil_forget`,
`echo_veil_list`, `echo_veil_doctor`, and explicitly confirmed
`echo_veil_reindex`. Remember, refresh, promote, and forget are always explicit
operations. Recall advances the memory lifecycle and can return
confidence-gated metadata without revealing a payload. List is bounded
administrative inventory only; it is non-semantic, lifecycle-neutral, and
must not be bulk-injected into a model prompt.

The bundled `echo-veil-memory` ritual is the behavioral authority for Codex and
Claude Code. OpenClaw registers the same policy through its exclusive memory
capability and enforces it with an early reply claim, protected prompt
construction, and a one-use pre-model attestation when the model is pinned to
OpenClaw's own runtime. Algo CLI injects the ritual directly into protected
ordinary-chat and Agent Block prompts. Codex and Claude Code bundle a shared
root-prompt and `Agent`-input preflight, OpenCode provides a native
`chat.message`/`chat.params` root gate plus a `Task` boundary, and Pi enforces
the ritual through input, pre-model, agent-start, and tool-call lifecycle
hooks. Hermes pairs ephemeral `pre_llm_call` context with an exact
session/task/turn and per-request-nonce `llm_execution` provider gate. The
`echo-veil-shielded-run` command gives Codex, Droid, Goose, and Hermes a
separate headless boundary that completes protected preflight before the host
process exists. The
required behavioral
contract is a doctor-backed preflight, minimal
recall for substantive tasks, Contextual Logic for causal or decision
questions, ambiguity/conflict preservation, and a stop instead of a plaintext
memory fallback. The host enforcement tier below determines the exact
lifecycle boundary repository code currently proves.

Run `python scripts/verify_host_authority.py --installed` for the
machine-readable evidence matrix. It reports source-digest drift, installed
version drift, externally unbound evidence, repository-only integrations,
conditional gates, and blocked hosts separately. A matching executable is
never promoted into a host-gate
claim: the report binds recorded smokes to their exact Echo source artifacts
and tested host versions, while the release procedure still reruns the live
provider and outage smokes.

Ordinary MCP hosts receive only these nine tools. Profile-key rotation and
previous-key retirement remain hidden and are rejected unless a separately
reviewed operator MCP process starts with `--operator-tools`. RPC maintenance
remains available for explicit operator workflows. Bundled agent configs do
not enable the operator profile.

Remember compact seed crystals, not transcript dumps. Live may temporarily hold
up to 20,000 characters of current state; Short-Term is capped at 12,000,
Contextual Logic at 4,000, and Long-Term at 2,000. Transcript-shaped payloads
are rejected outside Live, and Echo Veil never auto-summarizes or truncates
them. Use `echo_veil_refresh_live` for active state: unchanged content renews
its shielded contract, while changed content creates an explicit protected
superseding version.

Recall may be restricted to named semantic layers without changing scores.
Context tracing first retrieves at most two protected Contextual Logic roots
through the same confidence policy, then returns only bounded, authenticated
outgoing evidence links. Linked evidence is not independently query-scored and
the tool does not synthesize an answer.

If local Ollama or the configured model is unavailable, every full adapter can
use the same existing profile through an explicitly degraded read-only layer.
It returns only strong encrypted keyed-term matches, marks
`semantic_available=false`, and disables remember, forget, reindex,
refresh, promotion, inferential recall, and lifecycle mutation until semantic
service is restored.
These results are lexical availability hints, not semantic or authoritative
recall. It still authenticates and decrypts the same shielded semantic-layer
contract for each returned record. Full callers preserve both leading
candidates whenever `ranking_ambiguous=true`; the common RPC/MCP boundary
enforces at least two recall slots for legacy callers. Recall also keeps the
strongest authenticated same-topic current pair together and reports it as a
bounded `possible_conflict` group. Callers preserve every returned group member
and never infer compatibility or a resolution.
The read-only availability mode can return a bounded context trace only when
the logic root passes its conservative keyed predicate check; every linked
record still authenticates and the whole response remains degraded.
Required Algo CLI, OpenClaw, Codex, Claude Code, Pi, and OpenCode
model-turn gates are stricter: they stop the qualified turn boundary when
semantic Qwen3 readiness is unavailable rather than injecting degraded hints
as if the semantic preflight succeeded. Shielded headless Codex, Droid, Goose,
and Hermes runs apply the same rule before starting the host executable.

Install the Python command before using a standalone host configuration:

```bash
uv tool install --from /absolute/path/to/echo-veil echo-veil
ollama pull qwen3-embedding:latest
echo-veil-agent --profile smoke-test-qwen3 --embedder ollama \
  --scope local-user --caller smoke-test \
  --embedding-model qwen3-embedding:latest --embedding-dimension 1024 doctor
```

Codex and Claude Code plugin bundles invoke the installed
`echo-veil-agent` and `echo-veil-preflight-hook` entry points, so install the
matching Echo Veil distribution before enabling them. Linked OpenClaw and Pi
adapters can auto-detect this checkout when loaded from the repository.

| Host | Adapter | Enforcement tier | Install or validate |
| --- | --- | --- | --- |
| Algo CLI | In-process protected-memory authority + injected ritual | **Hard pre-model gate** in required mode; legacy memory is not loaded or searched | Enable required protection only after Algo CLI's Echo readiness and regression gates pass; see `integrations/algo-cli/README.md` |
| AIP | Artifact-bound provider gate + fresh-process RPC backend | **Hard runtime pre-provider gate** for Agent, SDK, workflow, chat, stream, and vision generation; no plaintext/RAM shadow store | Install the exact reviewed AIP wheel, verify `aip authority-receipt`, then require current AIP evidence; see `integrations/aip/README.md` |
| OpenClaw | Exclusive native memory capability + nine tools + three-stage turn attestation | **Hard OpenClaw-runtime pre-model gate** plus exclusive memory routing; the native Codex app-server runtime is not a qualified path | Select the memory slot, enable both required hook permissions, disable built-in `session-memory`, pin each protected model to `agentRuntime.id="openclaw"`, then run a zero-model outage smoke |
| Hermes | Shield-owned headless launcher plus native pre-LLM/execution plugin and stdio MCP | **Hard shielded memory-only gate** through `echo-veil-shielded-run hermes`; ordinary plugin mode remains conditional on visible plugin load | Install the reviewed plugin, then use the shielded launcher with an explicit local model; it isolates `HERMES_HOME`, disables both native memories, binds plugin digests and a launch nonce, and exposes only Echo tools |
| Codex | Trusted root plugin hook plus shield-owned headless launcher, implicit Agent Skill, and stdio MCP | **Hard direct root gate** with the exact hook trusted; **hard shielded headless gate** with parallel agents disabled; direct collaboration spawns are unqualified | Prefer `echo-veil-shielded-run codex`; it isolates Codex home/auth, injects required Echo MCP, disables native memory/Chronicle/goals/plugins/parallel agents, and defaults to read-only |
| Claude Code | Claude plugin, root/expansion/Agent hooks, implicit Agent Skill, and stdio MCP | **Hard root/Agent-spawn gate** in normal plugin mode; `--safe-mode` and `--bare` disable it, and only supported `Agent` tool spawns are covered | Disable Claude auto-memory without disabling hooks, validate the plugin, then run root-outage and Agent-spawn smokes |
| Pi | Native TypeScript extension with enforced pre-model gate + canonical memory skill | **Hard pre-model gate** through input, prompt-expansion, agent-start, and tool hooks | `pi install ./integrations/pi`, then run `/echo-veil-doctor` and `/echo-veil-preflight <intent>` |
| OpenCode | Global/project plugin + local MCP config + canonical memory skill | **Hard root/Task-spawn gate** in the normal plugin pipeline; `--pure` disables external plugins | Merge `integrations/opencode/opencode.json`, copy `integrations/opencode/.opencode`, run the plugin tests, then run healthy and zero-token outage smokes |
| Droid | Shield-owned headless launcher plus project/plugin MCP, skill, and native hooks | **Hard shielded headless gate**; native interactive hooks remain separately unqualified | Use `echo-veil-shielded-run droid`; Droid 0.180.0 `exec` bypasses native prompt hooks, so bare `droid exec` is outside the claim |
| Goose | Shield-owned headless launcher plus portable recipe | **Hard shielded headless gate**; the normal recipe remains policy-driven | Use `echo-veil-shielded-run goose`; see `integrations/goose/README.md` for the explicit Echo-only profile and recipe distinction |
| Mercury | Readiness-only guarded Agent Skill; incompatible with singular-authority mode | **Blocked for singular authority** because native mutable memory remains active | `mercury skills install --from ./integrations/mercury/SKILL.md`; disabling Second Brain still leaves native mutable memory, so payload operations remain blocked |

Algo CLI required mode, OpenClaw's pinned runtime, Pi, and a loaded Hermes
shield plugin currently own broad tested model-turn stop boundaries. Codex and
Claude Code hard-stop root user turns. Claude Code intercepts supported
`Agent` tool calls before subagent creation; OpenCode
does the same for root turns and supported `Task` calls. The Codex, Claude Code,
and OpenCode root boundaries are installed-host qualified. Their
Agent/Task-spawn boundaries retain repository/schema evidence but still require
installed provider smokes; Codex direct collaboration is currently known to
bypass `PreToolUse` and is excluded. The deny-only
`ECHO_VEIL_FORCE_AGENT_PREFLIGHT_FAILURE` and
`ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE` controls isolate the child boundary
without failing a healthy root preflight; they are qualification controls, not
runtime modes. Direct Codex root
claims apply only while the exact hook hashes are enabled and trusted. The
shielded Codex launcher owns a separate process boundary and disables every
current parallel-agent feature instead of relying on that bypassed hook. Claude
Code must not use `--safe-mode` or `--bare`; OpenCode must not use `--pure`;
Droid native interactive hooks must not be suppressed through
`allowManagedHooksOnly`, but Droid 0.180.0 `exec` bypasses native prompt hooks
and is explicitly unqualified. The shielded Droid launcher blocks before
process creation and disables `Task`, preventing an unpreflighted sub-droid
path. The shielded Goose launcher uses `--no-profile`, `--no-session`, and one
explicit Echo extension; the normal Goose recipe remains policy-driven. Direct
`SubagentStart` is not used as the gate because
the current host APIs cannot block creation at that event. AIP enforces
required memory-backend selection plus a common runtime provider boundary;
manually constructed raw providers are excluded. Ordinary Hermes plugin mode remains
conditional on visible plugin load because the host has no required-plugin
startup policy. The separate shield-owned Hermes path requests a plugin-defined
command that is registered only after the required hook and middleware, so
registration failure cannot reach a model turn. That qualified path is
one-turn, loopback-provider, and Echo-tools-only; it does not qualify every
Hermes mode. The
canonical Claude host identifier passed to the
shared preflight is
`claude-code`.

Mercury's current native Short-Term, Long-Term, and Episodic stores do not have
an all-memory-off switch. `SECOND_BRAIN_ENABLED=false` only replaces the
structured Second Brain with basic Long-Term fact search. Echo Veil support
therefore requires an upstream backend or structured hook that suppresses all
native mutable stores and fails closed before a model request; the bundled
skill deliberately performs doctor only.

Each full adapter defaults to the versioned
`echo-universal-qwen3-v1` Qwen3 profile and binds a stable host identity into
write provenance. Algo CLI adds both `caller:algo-cli` and
`algo-cli:<source>`. The shared default is intentional only for harnesses that
represent the same local user and authorization domain; a different user,
trust boundary, or embedding identity requires a different profile. Each
operation still acquires Echo's exclusive profile lease before loading Live
L1. Long-lived MCP servers release the startup probe and open one adapter per
tool call, while Algo opens one per operation, so concurrent hosts serialize
instead of retaining stale process-local L1 snapshots. Direct SDK callers must
close their adapter explicitly.

The full adapters use `qwen3-embedding:latest` through loopback-only Ollama with
1,024-dimensional output and instruction-aware recall queries. The model is not
downloaded automatically. The deterministic hashing backend remains an
explicit test/legacy keyword backend; it is not the outage layer. The outage
layer reads the existing keyed index and never substitutes incompatible
vectors. None of these modes is the production CKKS/enclave/ZKP profile,
silently captures conversations, or replaces a host's payload authorization
policy.

Every scoped-v2 memory also carries an encrypted record-bound contract for
Live, Short-Term, Long-Term, or Contextual Logic. Layer, provenance, retention
state, promotion history, and typed logic relationships use the same rotating
profile shield as payloads and vectors. Long-Term is available only through
`echo_veil_promote`; a caller cannot bypass Short-Term review with a direct
remember request.

Run `uv run --locked python scripts/quality_benchmark.py` before primary use,
then benchmark the real authorized corpus. Keep bundled profile names stable
when their protected embedding identity is compatible. Run doctor before
switching profiles; use `scripts/migrate_agent_profile.py` to re-embed a
compatible non-empty profile into a fresh scoped Qwen3 target without a
plaintext export. Incompatible embedding identities fail closed.
