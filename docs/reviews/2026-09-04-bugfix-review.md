# Bug review and patch verification — 2026-09-04

The patches address preflight evidence integrity, Grok's child-hook decision,
broker startup/recovery, and operator-test profile isolation. The follow-up
resolved all three repository source-authority failures: the full Python suite
now passes with **791 passed and 10 skipped**. Installed-host qualification
remains explicitly pending; repository validation does not renew it.

Existing uncommitted contextual-preflight, Codex-version, and documentation
changes were preserved. No active memory profile was migrated, no global plugin
was installed, and no release was published.

## Findings and changes

1. **Preflight could accept an incomplete candidate set.** Duplicate recall IDs
   counted as separate ambiguous candidates. Conflict groups could refer to
   missing or duplicate members or an unprotected topic basis; contextual roots
   lacked equivalent pair-preservation checks. Both unsigned and signed
   producers now check the actual identities and complete group membership
   before compaction or signing. The shared boundary is
   `src/echo_veil/agent_preflight.py::_validate_candidate_integrity`.

2. **A timed-out probe could remove a live broker socket.** A congested listener
   was treated as stale, allowing a second startup to unlink its endpoint.
   `src/echo_veil/agent_broker.py::_remove_stale_socket` now requires a refused or
   missing listener before removal. An inconclusive timeout fails without
   changing the existing endpoint.

3. **Broker startup errors could be masked and cleanup skipped.** Joining an
   unstarted writer or connection thread replaced the original failure with
   `cannot join thread before it is started`. Startup now tracks successful
   thread creation, releases a connection slot when its thread fails to start,
   closes that connection, and preserves socket cleanup and the original error.

4. **Grok's child guard emitted the wrong decision dialect.** The adapter used
   Claude's nested permission decision, whereas the installed Grok 1.0.3 hook
   documentation specifies top-level `decision` and `reason`. Guarded child
   requests now receive a native deny response, including malformed requests.
   A parent-side successful recall cannot authorize a child without verified
   context delivery, so these requests are denied before opening memory. Grok
   still controls plugin loading and fails open on hook-process failure; this
   patch does not qualify Grok as a universal execution gate.

5. **Operator tests could exercise the wrong profile.** Inherited
   `ECHO_VEIL_PROFILE` redirected CLI calls away from their populated fixture,
   invalidating five backup/migration/diagnostic assertions. Every operator
   fixture now names its profile explicitly, and an autouse fixture supplies a
   different ambient profile to keep this regression covered. CLI environment
   semantics are unchanged.

Tests are in `tests/test_agent_preflight.py`, `tests/test_agent_broker.py`, and
`tests/test_operator_cli.py`. Grok metadata, the integration guide, the local
security contract, and the changelog describe the resulting behavior.

## Initial verification

- Before the runtime patches, 22 new failure cases reproduced the defects;
  the two initial legitimate controls passed.
- All **30 expanded focused regression cases passed**, verifying distinct
  complete recall/context pairs,
  malformed-input rejection, native Grok denial, preservation of a live broker,
  recovery of a confirmed stale socket, and cleanup after thread-start failure.
- `uv run --locked pytest -q --tb=short`: **776 passed, 10 skipped, 3 failed**.
  All three failures are in `tests/test_host_authority.py` and arise from the
  recorded source-authority digest being stale. No test or authority gate was
  disabled or weakened to accept the new bytes.
- Ruff lint and formatting, Mypy, `scripts/security_scan.py`,
  `scripts/privacy_scan.py`, and `git diff --check`: passed.
- OpenClaw: 15 tests and type checking passed. Pi: 24 tests and type checking
  passed. OpenCode: 10 tests and syntax checking passed.
- The actual pinned v0.7 consumers passed against current mixed-v2/v3 and
  fully-v3 profiles: OpenClaw, Pi, OpenCode, and the shared Python consumers for
  AIP, Claude Code, Codex, Droid, and Hermes. All 16 pinned files were reverified
  after execution. The old core correctly rejected a v3-activated profile.
- `grok plugin validate ./integrations/grok`: passed. This validates the plugin
  structure, not a live model or child process.
- `scripts/verify_host_authority.py --installed --text`: exit 2, reporting
  stale source evidence for every applicable host and Mercury blocked.

Preflight RPC/receipt, runtime-status, telemetry, evidence, and storage-contract
identifiers were not changed. At this checkpoint, no live model, protected-host
outage, or new installed-artifact qualification was claimed.

## Follow-up: source-evidence and test repair

The three failing assertions reproduced before this follow-up. Shared source
changes had invalidated every host's recorded qualification, and the Codex and
Grok adapter digests had also drifted. The repository bindings now match the
reviewed bytes, but every formerly qualified host is explicitly
`release_pending`, alongside Codex and Pi. Grok remains `repository_only` and
Mercury remains `blocked`. Historical test dates, tested versions, and smoke
records were not renewed or presented as current installed qualification.

The replaced bindings are retained here for audit:

| Binding | Previous SHA-256 | Reviewed SHA-256 |
| --- | --- | --- |
| Shared source | `0e0a056c899a00dbdeaa36ee33349916a925f8e01743f07859c71d0b4e4b2695` | `d8e51b138cdea011853287746ac74eb950ffad14f3a7d38fb8f38c3384e6ee10` |
| Codex adapter | `abbf71ce6c1eefa077304b1720e425a4d5f261b7335507f27f93138739e0760d` | `36f36db73aa9054f86b862a8a973501e9d77be09280cdaa5e12cd36d0daa095a` |
| Grok adapter | `04e78630d102a8b3b7a669293632d7ac8567411bde0438daa6b24b1edc344d9d` | `3ab03ef7084268d5265292175bcb8dab5fe3b99a3a7e1f7c23d4c6e6dee55729` |

This uses the existing evidence states; the verifier, required-current gate,
manifest schema, and harness protocols were not changed. The release guide and
integration overview now explicitly separate repository review from historical
installed evidence. The documentation-contract test was updated to require
that distinction instead of the previous current-qualification claim.

Follow-up files: `integrations/authority-evidence.json`,
`tests/test_host_authority.py`, `tests/test_agent_adapters.py`,
`integrations/README.md`, `docs/RELEASING.md`, `CHANGELOG.md`, and this report.

`tests/test_host_authority.py` now exercises the qualified artifact-mismatch
path with an isolated source fixture, so a pending real installation cannot
mask the unit test or need to be promoted to make it pass. Twelve added cases
cover legitimate qualified/conditional controls, missing and changed runtimes,
independent shared/adapter source drift, and CLI rejection of pending,
repository-only, and blocked evidence even with matching artifacts.

Final verification:

- `uv run --locked pytest -q tests/test_host_authority.py --tb=short`:
  **20 passed**; all three original assertions are resolved.
- `uv run --locked pytest -q --tb=short`: **791 passed, 10 skipped**.
  A second full run with `-rs` produced the same result. Nine skips require
  Windows-native contracts; one requires the unconfigured native macOS custody
  helper. This follow-up does not claim those platform qualifications.
- Ruff lint/format, Mypy, security/privacy scans, and `git diff --check`: passed.
- `uv run --locked python scripts/release_check.py`: passed for **0.8.0**.
- `uv run --locked python scripts/verify_host_authority.py --installed --text`:
  exit **0**, source bindings current, zero current runtime boundaries.
- `uv run --locked python scripts/verify_host_authority.py --require-current codex
  --require-current pi --text`: exit **2**, correctly rejecting pending installed
  qualification. Matching-version and matching-artifact negative controls also
  pass in the focused suite.

Outcome: **fixed for repository validation**, with the independent installed
release gate still pending. No live-host healthy/outage smokes, new immutable
artifact installation, commit, tag, release, or deployment were performed.
Rust, Worker, and infrastructure checks were not repeated in this follow-up
because those components were unchanged. Exact installed-artifact and live-host
requalification remain necessary before promoting any affected boundary.
