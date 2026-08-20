# Secure release process

Echo Veil releases are built from an existing annotated semantic-version tag.
The workflow creates a draft GitHub release so its artifacts can be reviewed
before publication. It does not deploy cloud infrastructure or publish to PyPI.

## One-time GitHub configuration

These controls live in GitHub and cannot be enforced by repository files alone:

1. Protect the default branch (`master`) with a ruleset that requires pull requests, at least one
   approval, CODEOWNER review, dismissal of stale approvals, approval after the
   latest push, resolved conversations, signed commits, and all CI/security
   checks. Block force pushes, deletions, and administrator bypass.
2. Require these checks: every `CI` job, every `Security` job, every `CodeQL`
   language, and `Dependency Review`.
3. Enable private vulnerability reporting, Dependabot alerts, secret scanning,
   push protection, and immutable releases.
4. Require full-length commit SHAs for GitHub Actions. Allow only the action
   owners referenced by the workflows.
5. Create a `release` environment restricted to tags matching `v*`. Require an
   independent reviewer and prevent self-review.
6. Protect tags matching `v*` from updates and deletion.

CodeQL, artifact attestations, and protected-environment reviewers are available
at no charge when the repository is public. A private repository requires the
applicable paid GitHub security and Enterprise features; the corresponding
workflows intentionally fail closed when those services are unavailable.

The hosted adapter gate downloads the exact qualified OpenClaw validation
runtime, verifies its pinned SHA-512 before installation, installs it without
lifecycle scripts into a disposable directory, and exposes only that executable
to the isolated loader test. Review and update the version, published artifact
digest, and expected version output together when requalifying OpenClaw.

If PyPI publishing is added, configure a PyPI Trusted Publisher bound to the
`release` environment. Do not add a long-lived PyPI API token.

## Release checklist

1. Confirm the worktree contains only intended changes and all dependency lock
   updates have been reviewed.
2. Update the version in `pyproject.toml`, `src/echo_veil/__init__.py`,
   `.codex-plugin/plugin.json`,
   `.claude-plugin/marketplace.json`,
   `integrations/claude-code/.claude-plugin/plugin.json`,
   `integrations/droid/.factory-plugin/plugin.json`,
   `integrations/hermes/plugin/plugin.yaml`,
   `integrations/mercury/SKILL.md`,
   `integrations/openclaw/package.json`,
   `integrations/openclaw/openclaw.plugin.json`, and
   `integrations/opencode/package.json`, and `integrations/pi/package.json`.
   Update their package lockfiles and
   `integrations/openclaw/deployment-lock.json` in the same reviewed change.
   Set the deployment lock's `source_date_epoch` once for the release date;
   both local and hosted builds must reproduce the wheel and the allowlisted
   OpenClaw archive built by `scripts/build_openclaw_archive.py`.
3. Move the changelog entries from `Unreleased` into the new version section.
4. Run:

   ```bash
   uv lock --check
   uv sync --locked --extra dev --extra enclave-origin
   uv run ruff check src tests scripts examples
   uv run ruff format --check src tests scripts examples
   uv run mypy src/echo_veil src/echo_veil_origin scripts examples --ignore-missing-imports --no-error-summary
   uv run pytest -q
   python scripts/security_scan.py .
   python scripts/privacy_scan.py . --git-history
   python scripts/release_check.py
   cargo fmt --manifest-path crates/echo-veil-zkp/Cargo.toml -- --check
   cargo clippy --locked --all-targets --manifest-path crates/echo-veil-zkp/Cargo.toml -- -D warnings
   cargo test --locked --manifest-path crates/echo-veil-zkp/Cargo.toml
   npm --prefix cloudflare/enclave-gateway ci --ignore-scripts
   npm --prefix cloudflare/enclave-gateway audit --audit-level=high
   npm --prefix website ci --ignore-scripts
   npm --prefix website audit --audit-level=high
   npm --prefix website run lint
   npm --prefix website test
   npm --prefix integrations/openclaw ci --ignore-scripts
   npm --prefix integrations/openclaw audit --audit-level=high
   npm --prefix integrations/openclaw run check
   npm --prefix integrations/openclaw run plugin:validate
   npm --prefix integrations/openclaw test
   npm --prefix integrations/pi ci --ignore-scripts
   npm --prefix integrations/pi audit --audit-level=high
   npm --prefix integrations/pi run check
   npm --prefix integrations/pi test
   npm --prefix integrations/opencode ci --ignore-scripts
   npm --prefix integrations/opencode audit --audit-level=high
   npm --prefix integrations/opencode run check
   npm --prefix integrations/opencode test
   uv run --locked pytest -q tests/test_hermes_plugin.py
   ```

   Also run `tests/test_agent_adapters.py`, validate and install the
   repository-root Codex and Claude Code plugins through their local marketplace
   descriptors, and validate the Goose recipe with `goose recipe validate`
   before tagging. For AIP, require both `aip --version` and the payload-silent
   `aip authority-receipt`; its PEP 610 wheel hash and installed `RECORD`
   integrity must match the exact manifest binding. Review Codex's exact hook
   hashes through `/hooks`, disable
   Codex native memories, disable Claude Code auto-memory without disabling
   plugin hooks, and explicitly disable OpenClaw's built-in `session-memory`
   hook. Run `python scripts/verify_host_authority.py --installed` and review
   every boundary as current, conditional, externally unbound,
   repository-only, release-pending, blocked, or stale. A Pi or Codex boundary
   recorded as `runtime_release_stale` must not be promoted merely because the
   host executable version matches.
   For Pi, verify `integrations/pi/artifact-receipt.json` from both TypeScript
   and Python and pin that exact authority ID in the isolated launcher. For
   Codex, run the receipt-only mode with
   `echo-veil-shielded-run codex --model MODEL --print-codex-artifact-receipt`,
   review the path-free receipt, install the
   exact wheel, and rerun both headless and isolated-interactive modes with its
   out-of-band authority ID. One-byte drift in the host executable, wheel,
   entry points, plugin, hooks, MCP config, model/configuration, or broker
   authority must block startup.
   Use repeated `--require-current HOST` arguments for the installed boundaries
   the release claims. This digest and version check does not replace the live
   smokes. Run zero-model outage smokes for OpenClaw, Codex, Claude Code, Pi,
   OpenCode, and Algo CLI in isolated host profiles. Run both healthy and
   forced-outage probes through `echo-veil-shielded-run` for Codex, Droid,
   Goose, and Hermes; the outage must return before the host process starts. The Codex
   probe must retain its Echo-only MCP, native-memory shutdown, and
   parallel-agent shutdown flags. It must use an isolated temporary Codex home
   and must not load the operator's ambient skills, cache, goals, plugins, or
   session state. Separately exercise the supported Claude
   Agent and OpenCode Task spawn paths. Direct Codex collaboration remains
   excluded until its host exposes a blockable task-specific event. Direct
   Codex also remains non-singular while any competing mutable-memory plugin is
   exposed. Direct ambient Pi stacks retain extension-order risk; use the
   isolated receipt-bound Pi launcher for a singular claim.
   Run `uv run --locked python scripts/quality_benchmark.py` with local Qwen3.
   The release gate requires zero lost ambiguous/conflicting candidates, zero
   unrequested preflight mutations, zero provider/agent/tool activity on forced
   outage, poisoned memory remaining escaped untrusted evidence, and warm
   concurrent Pi/Codex broker p95 below 500 ms on the qualification machine.
   Run `uv run --locked python scripts/qualification_benchmark.py` for the
   1K, 10K, and 100K 1,024-dimensional durable-index tiers. It must preserve
   exact top-one targets, keep exact reranking below ten percent of each
   corpus, survive an integrity-checked reopen, serve concurrent WAL readers
   during a bounded write, and recover correctly from abrupt process exit on
   both sides of commit. This is a local index/storage gate, not a semantic,
   distributed-scale, or physical power-removal claim.
   OpenClaw must also block a hot-reload attempt to re-enable native
   session-memory. Hermes and normal Goose recipe mode should be smoke-tested in isolated
   temporary host profiles so release checks never mutate an operator's
   personal agent configuration. Hermes must show `echo-veil-shield` as loaded,
   disable both built-in memory flags, pass a healthy preflight, and prove its
   deny-only outage control returns zero provider calls and zero usage.
   Its shield-owned run must additionally validate the exact plugin digest,
   use an isolated temporary `HERMES_HOME`, request the plugin-defined
   `echo-veil-run` command, expose only the Echo toolset, complete a real local
   provider turn, and stop before Hermes creation on outer preflight failure.
   OpenCode must run through its normal plugin pipeline; `--pure` is a negative
   control that intentionally disables the Echo gate. Bare `droid exec` is a
   negative control in Droid 0.180.0 because it bypasses native prompt hooks;
   interactive Droid root/Task hooks require their own authenticated installed
   smoke before any interactive hard-gate claim.

   For the OpenClaw deployment selected as a singular memory authority, run
   `python scripts/verify_openclaw_deployment.py --text` after the healthy and
   outage smokes. It must bind both installed artifacts to
   `integrations/openclaw/deployment-lock.json`, report 9/9 tools and 3/3 hooks,
   reject mutable checkout paths and native `session-memory`, and pass with no
   OpenClaw security warnings. Use `--require-production-ready` only for a
   deployment whose external enclave and cryptographic review are complete.

   For a release that promotes an application integration to a protected
   default, also satisfy the hard gate in
   [`LOCAL_AGENT_SECURITY.md`](LOCAL_AGENT_SECURITY.md). In particular, run its
   black-box ordinary-write → disk-confidentiality → fresh-process-restart →
   authorized-scope-recall test in the actual installed host runtime. A sibling
   checkout, editable import, source/distribution version mismatch, missing
   backup/restore exercise, or missing independent security review blocks that
   promotion even when repository unit tests are green.

5. Merge only after required checks and independent review pass.
6. Create and push an annotated tag from the protected release commit:

   ```bash
   git tag -a v0.7.0 -m "Echo Veil v0.7.0"
   git push origin v0.7.0
   ```

7. Manually run the `Release` workflow with that exact tag.
8. Verify the draft's changelog, wheel, sdist, OpenClaw plugin archive, SBOM,
   `SHA256SUMS`, and GitHub provenance attestation. Install the wheel and plugin
   archive in clean, isolated environments.
9. Publish the draft only after review. With immutable releases enabled, the
   tag and assets become unchangeable after publication.

## Consumer verification

Download the release assets, then verify their hashes:

```bash
sha256sum --check SHA256SUMS
```

For a public repository, verify GitHub provenance with the GitHub CLI:

```bash
gh attestation verify echo_veil-0.7.0-py3-none-any.whl \
  --repo Seabass-up/echo-veil
```
