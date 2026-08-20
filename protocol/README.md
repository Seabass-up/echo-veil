# Echo Veil protocol compatibility shield

`registry-v1.json` is the authoritative inventory for every externally consumed
Echo Veil contract. It separates harness protocols from internal storage
formats so a record-envelope migration cannot silently become a preflight
protocol migration.

The compatibility rules are deliberately asymmetric:

- signed objects use exact field sets and reject unknown schemas;
- unsigned surfaces permit only the optional fields listed in the registry;
- `preflight_v2`, `echo-veil-preflight-v2`, and the existing v1 runtime,
  evidence-budget, telemetry, broker, and artifact contracts retain their
  identifiers;
- the installed unsigned `preflight` compatibility RPC remains registered for
  harnesses that have not moved to signed receipt consumption;
- `capabilities_v1` is a separate unsigned readiness surface and does not
  authorize a model turn;
- record-envelope v2/v3 is visible only to the core. Harnesses must behave the
  same for v2, v3, and mixed profiles.

`fixtures/compatibility-v1.json` is language-neutral. Python, TypeScript, and
JavaScript adapter tests load it directly. Fixture data is synthetic and
contains no user memory, credential, private key, personal path, or production
authority.

The v3 rows currently prove only that consumers do not read a storage-version
field. They are not evidence that a v3 core exists. Phase 3 must replace those
boundary simulations with real dual-reader, mixed-profile, migration, restart,
and rollback tests before v3 writes can be enabled.
