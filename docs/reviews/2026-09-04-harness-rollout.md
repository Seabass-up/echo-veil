# Installed harness rollout progress — 2026-09-04

## Outcome and boundary

The rollout is **partially verified, not operationally promoted**. Candidate
artifacts are installed side by side with the existing runtime. No active
gateway, user profile, default launcher, key custody, or model service was
replaced. All marker records and restore targets are isolated synthetic data.
Claude Code is excluded at the operator's request; its authenticated tests
are deferred, not passed.

The harness protocol remains `preflight_v2`; no record migration or production
activation was performed. The tested profile remains `local-staging`, not
enclave-ready or host-compromise-protected.

## Fixes found through installed tests

1. Pi 0.84.4 was rejected by the 0.84.2 executable/receipt pin. Update the exact
   Python/TypeScript pins, dependency lock, and package receipt together.
   Older versions and altered receipts remain rejected; no range is accepted.
2. Healthy Ollama operator backup failed because the availability wrapper is
   not the concrete semantic adapter required by operator commands. Recovery,
   qualification, and migration now open that adapter without availability
   fallback. A regression reproduced the failure, then passed healthy backup
   and proved an embedding outage creates no backup and leaves profile files
   unchanged. Agent recall fallback behavior is unchanged.
3. OpenClaw 2026.9.1 requires source/capability consent and changed its doctor
   success message. The isolated validator now accepts an explicit
   `--confirm-local-source` opt-in and exact known success messages. Consent
   applies only to fresh temporary host state. Nine tools, three hooks, slot
   selection, and diagnostics checks remain required.
4. OpenCode initializes every exported function in a discovered plugin file.
   It attempted to initialize Echo's capabilities parser and failed. Strict
   validators now live in `.opencode/lib/echo-veil-contracts.js`; the entry
   point exports only `EchoVeilShield`. A regression exercises export
   enumeration, and release checks require the helper in the source archive.
   The fixed installed plugin progressed to provider auth, which failed 401.

## Artifact and final-candidate smokes

- Echo wheel SHA-256:
  `97b02d6edcc6c829040fb0b805330c097611dc6ab9fc78330aa9ff2025bf2f06`.
- Pi package authority:
  `sha256:1683c553ccfc21bb79ef222873eed94682827e213621b36d865d63437c93cb7b`.
- Installed Echo verification checked 46 package files and three console entry
  points against the retained, SHA-256-pinned wheel.

Each healthy smoke returned a marker found only in Echo memory, not the query.
Outages used an isolated non-listening loopback endpoint; the real embedding
service remained available.

| Installed host and tested mode | Healthy | Outage | Healthy elapsed |
| --- | --- | --- | --- |
| Codex 0.149.1, isolated headless | Marker, exit 0 | Blocked, exit 2 | 7.269 s |
| Pi 0.84.4, isolated one-turn | Marker, exit 0 | Blocked, exit 2 | 8.192 s |
| Hermes 0.20.6, local Echo-only launcher | Marker, exit 0 | Blocked, exit 2 | 31.375 s |
| Goose 1.45.0, shielded Echo-only launcher | Marker, exit 0 | Blocked, exit 2 | 6.512 s |
| Droid 0.183.0, shielded headless | Marker, exit 0 | Blocked, exit 2 | 50.812 s |

Codex and Pi also rejected wrong artifact pins. These are process-level smokes,
not independent network tracing, all tool-consent paths, or proof that ambient
configurations are singular. An earlier Droid run took 96.012 seconds; its
latency variability remains a QoS concern.

The installed candidate created and authenticated an encrypted backup, passed
its restore drill, restored into a different profile, and recalled the marker
in a fresh process from that restored profile. This is a synthetic recovery-set
test, not a Time Machine destination restore or operational-data migration.
The operator fix was exercised with real Qwen3.

Local repository checks passed: 793 Python tests (10 platform/helper-dependent
skips), Ruff lint/format, Mypy, security/privacy scans, release validation,
24 Pi tests, 11 OpenCode tests, and the current OpenClaw loader check. Repeated
wheel and OpenClaw archive builds produced identical bytes. These results are
not a substitute for the pending independent review or operational rollout.

## Remaining rollout gates

- **Codex/Pi/Hermes/Droid/Goose:** publish reviewed immutable artifacts, then
  qualify the intended operational installation, tools, consent, backup, and
  custody boundaries. Direct Codex children remain excluded.
- **OpenClaw:** current 2026.9.1 loaded nine tools and three hooks in the
  isolated validator. The live gateway still uses plugin 0.7.0. The deployment
  verifier also finds required explicit `agents.list` configuration absent.
  Review effective agent policy and complete staged healthy/outage/reload tests
  before switching the live archive and wheel.
- **OpenCode:** corrected plugin loads, but OpenAI OAuth refresh returns 401.
  Renew authentication before healthy root and permitted/denied Task tests.
  A generic error exit is not counted as a successful outage gate.
- **Algo CLI:** inspected checkout is clean at `cb310d7`; the old dirty-tree
  warning was stale. Active 0.18.0 has no Echo distribution. Required source
  identity targets `271ebaa959aabd7a83cf338d30cd0fa1c7338488`, not this wheel.
  Requalify its consumer and release gates; do not bypass the source pin.
- **AIP:** installed RECORD integrity is true, but its wheel hash differs from
  the expected binding. Requalify that artifact, not merely version 0.1.1.
- **Claude Code:** excluded by the operator. Do not purchase access or change
  credentials; preserve adapter tests without claiming live qualification.
- **Grok/Mercury:** retain their documented limited/blocked modes.
- **Release:** independent review, protected release commit, annotated tag,
  draft artifact/provenance verification, and staged operational promotion
  remain outstanding. This report does not imply a tag or deployment.
