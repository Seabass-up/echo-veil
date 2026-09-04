# Isolated artifact qualification — 2026-09-04

## Scope and result

The reviewed implementation was committed as
`4c41761cd827ad35d7c6347e9b7d95f76ed0c1a2`. Its wheel was installed into a
separate virtual environment from a retained, explicitly SHA-256-pinned local
file URL. All memory used below was synthetic in a separate state directory.
The operator's active profiles, installed integrations, and model services were
not reconfigured or stopped.

This is bounded installed-artifact evidence for Codex 0.149.1 and Pi 0.84.2,
not a blanket promotion of the host-authority manifest. Active Pi 0.84.4 was
not downgraded or qualified by these tests. No preflight protocol changed.

## Artifacts and packaging

Two independent builds produced identical wheel, normalized source archive,
and OpenClaw archive bytes. The runtime artifacts are:

- Echo 0.8.0 wheel SHA-256:
  `62dcd1f5cb0f74f29102fcdafd620380d3a95a642faebf37c3a0152cb8b8058a`.
- OpenClaw archive SHA-256:
  `9c54480c6265186f11c4eddad3d7bd32049a4d74975d18ade233161f42a51d12`.
- Pi authority ID:
  `sha256:cef55d039e7b21918db18742b794b217908233413d2e6f9e4bca7a27cff1c2d4`.

The deployment lock was updated to the rebuilt wheel. Its historical
OpenClaw test date was not renewed, and OpenClaw remains release-pending.
Documentation-only follow-up changes require a new source archive; that
archive's checksum is recorded beside the final build, not self-referentially
inside this document.

Two invalid packaging routes were reproduced and rejected:

1. Plain `uv pip install` of a local wheel produced an empty PEP 610
   `archive_info`. Codex refused to issue an artifact receipt. Reinstalling the
   same bytes with the verified `#sha256=` URL fragment fixed the receipt;
   no installed metadata was manually rewritten.
2. Plain `npm pack` omitted Pi's required `package-lock.json`; verification of
   the extracted package failed. The supported full Echo source archive
   already includes the lockfile. Its extracted Pi directory verified and
   passed the live smoke. The invalid npm archive is not a release artifact.

## Verification

- Full repository suite: **791 passed, 10 skipped**. Nine skipped checks are
  Windows-native; one needs the unconfigured native macOS custody helper.
- Ruff lint/format, Mypy, security/privacy scans (including Git-history privacy
  review), and repository release validation passed.
- Pi's locked 0.84.2 dependency installation, TypeScript check, 24 tests, and
  zero-vulnerability npm audit passed. Its six receipt-bound files verified.
- The installed wheel performed protected remember, then retrieved the memory
  in a fresh RPC process; doctor reported adapter and local protection ready.
- Codex 0.149.1 headless, with `gpt-5.4-mini`, returned a marker present only
  in Echo memory, not in the submitted query. Exit 0; initial elapsed time
  8.314 seconds. Wrong artifact pin and simulated embedding outage returned
  exit 2 with the required-preflight failure and no marker output.
- Codex isolated interactive mode verified its distinct artifact receipt,
  visibly completed the UserPromptSubmit Echo hook, and returned the same
  memory-only marker. The existing model was retained when the host offered a
  model upgrade, preserving the reviewed model binding.
  A separate interactive run with a verified outage-configuration receipt
  visibly stopped at UserPromptSubmit after about eight seconds with
  `The model turn was blocked; no host memory fallback was used.`
- Pi 0.84.2 with local `gemma4:12b-mlx` returned the memory-only marker. The
  explicitly hash-installed wheel passed again in 2.293 seconds; the adapter
  extracted from the source archive passed in 4.462 seconds. Wrong pin and
  simulated embedding outage returned exit 2 with required-preflight failure.
- Outages used a separately bound, non-listening loopback port. The real
  Ollama endpoint and active gateway were not interrupted.

The installed-wheel Qwen3 benchmark passed **48/48 retrieval cases**, **14/14
unrelated rejections**, **17/17 offline keyword cases**, and **14/14 offline
rejections**. It preserved competing candidates and authenticated context
links. Concurrent Codex/Pi broker preflight p95 was **363.53 ms**, below the
500 ms gate; missing candidates, preflight profile mutations, and ritual
failures were all zero. The benchmark's instrumented forced-outage gate
recorded zero agent starts, provider calls, and tool executions. Those counters
are benchmark instrumentation, not independent network tracing of the live
host smoke processes.

## Remaining release boundaries

Keep affected hosts release-pending until the exact artifacts are released,
installed in the intended operational boundary, and rechecked there. This
does not qualify other host versions, ambient Codex/Pi configurations,
collaboration, every individual tool consent path, or the native custody
platform tests skipped above. Other harnesses need their own installed smokes.
No claim of an enclave, CKKS, remote attestation, or host-compromise protection
is added by these local tests.
