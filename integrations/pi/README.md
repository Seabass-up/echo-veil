# Echo Veil for Pi

This native Pi extension registers `echo_veil_remember`,
`echo_veil_refresh_live`, `echo_veil_promote`, `echo_veil_recall`,
`echo_veil_context`, `echo_veil_list`, `echo_veil_forget`, and
`echo_veil_doctor`, plus explicitly confirmed `echo_veil_reindex`, without
adding a shell-enabled tool. It sends bounded JSON
to `echo-veil-agent` over stdin and defaults to the shared
`echo-universal-qwen3-v1` profile with scope `local-user`. This shared default
is only for harnesses acting for that same local user and authorization domain;
configure a distinct profile for another trust boundary. Each RPC process
releases the profile before returning, so Pi does not retain a writer lease
between calls.
The package also declares `skills/echo-veil-memory/SKILL.md`, so Pi discovers
the same fail-closed preflight, minimal-recall, Contextual Logic, and
layer-discipline ritual used by Codex, Claude Code, and Hermes.

The extension enforces one canonical signed `preflight_v2` RPC in Pi's runtime.
The receipt binds the exact profile, scope, query digest, session, turn, model,
active-tool manifest, Pi artifact authority, evidence digest, embedding model,
random nonce, short expiry, ambiguity/conflict state, and allowed capabilities.
It uses lifecycle-neutral preview retrieval: repeating the preflight does not
observe, reinforce, decay, prune, or otherwise change memory state. Normally
only the leading result is injected; both leading candidates are retained when
ambiguity or protected-topic conflict requires them. The raw prompt is not
duplicated inside the evidence.

The evidence carries a compact `echo-veil-runtime-status-v1` object. A
host-validated `ritual_satisfied=true` means the exact turn already completed
doctor, recall, and applicable Contextual Logic checks, so the packaged skill
does not repeat them. Evidence is bounded to 16,000 characters and an estimated
2,400 tokens. When necessary, whole payloads are omitted before any record
shell; ambiguity/conflict IDs, provenance, and temporal metadata remain.
Payload-free telemetry reports only bounded stage timings, result count, and
whether Contextual Logic ran.

Pi verifies the Ed25519 receipt at its last enforceable provider boundary and
checks that the exact protected evidence is still present in the outbound
payload. Each subsequent provider turn receives and consumes a fresh receipt.
Session start, resume, and fork reset all authorization state; prompt-template
or skill expansion is rebound to the expanded query. Queued or steering input
is rejected until it can receive an independent turn. Missing, altered,
expired, replayed, cross-turn, cross-model, cross-tool, or stripped-context
receipts fail closed. Required preflight failure returns from the input hook,
so ordinary Pi input produces no agent start, provider request, or tool call.
Every Echo tool is registered as sequential.

The package and its pinned Pi `0.84.4` API are bound by
`artifact-receipt.json`. Both the shielded Python launcher and the extension
verify the exact source/package-lock hashes against an out-of-band
`ECHO_VEIL_PI_ARTIFACT_AUTHORITY_ID` pin. One-byte drift blocks startup.
Mutations and `allowInferential=true` require a fresh, one-use Pi UI
confirmation. Headless print mode has no confirmation UI, so those operations
remain blocked there.

A required model-turn preflight never accepts Always-Available results. When
semantic embeddings are unavailable, `/echo-veil-availability <intent>` can
manually display bounded authenticated keyed matches as visibly degraded,
non-authoritative evidence. That diagnostic is RPC-only, forces the encrypted
read-only store, resets cached doctor state, and never authorizes an agent,
provider call, tool call, inferential lookup, or mutation.

Mid-run steering and queued follow-up inputs are rejected because Pi can add
them to an existing agent loop without a fresh `before_agent_start` boundary.
Retry that input after the current run settles so it receives its own protected
preflight.

From an Echo Veil checkout:

```bash
npm --prefix integrations/pi ci --ignore-scripts
npm --prefix integrations/pi audit --audit-level=high
npm --prefix integrations/pi run check
npm --prefix integrations/pi test
pi install ./integrations/pi
```

For a pinned distribution, use `integrations/pi` from the verified Echo Veil
source archive and retain `package-lock.json` and `artifact-receipt.json`.
Plain `npm pack` omits the lockfile and does not produce a valid receipt-bound
Pi artifact. Verify the extracted directory before and after `npm ci` with
`python scripts/build_pi_artifact_receipt.py --directory DIRECTORY --check`
from the extracted Echo source root. Do not regenerate a receipt merely to
accept an incomplete package.

For the strongest supported Pi boundary, use the isolated one-turn launcher.
It keeps the prompt off the process command line, disables sessions, ambient
extensions, skills, templates, themes, context files, project trust, and all
built-in tools, loads only the receipt-bound Echo package, creates a clean
owner-only Pi home, and inherits only the selected provider credential:

```bash
export ECHO_VEIL_PI_ARTIFACT_AUTHORITY_ID='sha256:<reviewed receipt ID>'
printf '%s\n' 'your prompt' | echo-veil-shielded-run pi \
  --provider ollama \
  --model qwen3.6:35b-mlx
```

For a separately installed Pi package, also pass its absolute
`--pi-extension-dir`. The launcher obtains the profile-specific preflight
authority directly from the owner-only Echo profile and passes that exact pin
to Pi. For local Ollama, it creates only the requested model entry in the
temporary Pi catalog. Direct interactive installation retains Pi's ambient
non-memory tools and other extensions; because a later extension can alter a
provider payload after Echo's hook, direct mode is protected Echo recall but
is not the same singular, final-boundary claim as the isolated launcher.

For repeated Pi/Codex work, start one `echo-veil-agent broker` against the
profile and pass its owner-only Unix socket with `--broker-socket` or
`ECHO_VEIL_BROKER_SOCKET`. Pi then performs one bounded socket round trip per
preflight with no Python process spawn. The broker serializes both hosts, keeps
the profile/model warm, and returns only payload-free transport timings. A
missing or degraded broker blocks the required gate; it never turns the manual
Always-Available reader into an authorized preflight.

The `0.84.4` source and receipt are candidate artifacts, not yet a
released immutable installation. Host-authority reporting must keep the current
installed Pi runtime release-stale until the exact artifact is committed,
released, installed, and rechecked.

The linked checkout is detected automatically. For a standalone package,
install the `echo-veil-agent` command or set `ECHO_VEIL_AGENT_COMMAND` to its
executable path. `/echo-veil-doctor` validates the local shield without a model
call. `/echo-veil-preflight <intent>` verifies a signed, non-authorizing
preflight-v2 receipt without a model call. `/echo-veil-availability <intent>` is the separate
manual degraded read-only inspection path. None of these diagnostics authorizes
the next turn.

Remember and forget remain explicit user-authorized actions. The preflight
does not create memories or copy prompts into Echo Veil; it submits the bounded
intent for local retrieval and injects only the minimal validated result into
that model turn.
Remember creates Live, Short-Term, or typed Contextual Logic records;
Long-Term requires explicit promotion. The complete semantic contract is
record-bound ciphertext under the same scoped profile shield as payloads and
vectors.
Write compact seed crystals instead of transcript dumps. Transcript-shaped
payloads are accepted only as bounded Live state. Use
`echo_veil_refresh_live` to renew unchanged state or create a protected
superseding Live version when the content changes.
Recall preserves both leading candidates when `ranking_ambiguous=true` and
every returned possible-conflict group member when
`competing_memory_detected=true`; it never invents a conflict resolution.
Responses marked `degraded=true` are conservative lexical availability hints,
not semantic or authoritative recall.
Recall can restrict results to named semantic layers without changing scores.
Context tracing preserves root confidence gates and follows only bounded,
authenticated outgoing links; linked evidence is not an independent query
match and the tool does not synthesize an answer.
`echo_veil_list` is bounded administrative inventory, not semantic recall. It
does not reinforce or decay records and must not be injected wholesale into
model context.
The child receives only runtime essentials and the explicit local-adapter
environment allowlist; unrelated API keys and production Echo Veil crypto
secrets are not inherited. Child stderr is drained but never exposed to the
agent, and timeout/abort handling escalates from termination to forced exit.
The child also binds `caller:pi` into protected write provenance. That
transport marker does not count as durable Long-Term or Contextual Logic
evidence by itself.
