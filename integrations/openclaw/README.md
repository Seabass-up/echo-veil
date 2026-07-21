# Echo Veil for OpenClaw

This tool plugin exposes `echo_veil_remember`, `echo_veil_recall`,
`echo_veil_forget`, and `echo_veil_doctor`. It delegates to the repository's
Python adapter so OpenClaw and Codex use the same storage, encryption, decay,
and confidence policy.

For local development, link this directory so the plugin can auto-detect the
repository three levels above it:

```bash
openclaw plugins install -l ./integrations/openclaw
openclaw plugins enable echo-veil
openclaw plugins doctor
```

The package keeps OpenClaw as a peer rather than vendoring the host runtime or
its dependency tree. Run `npm run plugin:validate` with the supported OpenClaw
CLI installed before a release; CI compiles and tests the same SDK contract
without adding the host itself to Echo Veil's lockfile.

For a copied or packaged install, either install the `echo-veil-agent` console
script or set `plugins.entries.echo-veil.config.projectPath` to an Echo Veil
checkout. `stateDir` and `profile` select the encrypted local profile. Codex and
OpenClaw share memories only when both are configured with the same values.

The integration is opt-in: it does not capture every message or replace
OpenClaw's configured memory provider/context engine.

Recall preserves both leading candidates when `ranking_ambiguous=true` and
labels `degraded=true` results as non-semantic, non-authoritative availability
hints. Each response includes `host_transport.elapsed_ms` so fresh-process RPC
overhead can be tracked separately from Echo Veil's in-process recall time.
