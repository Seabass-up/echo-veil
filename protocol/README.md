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

The v3 rows are backed by real dual-reader, mixed-profile, bounded migration,
restart, key-rotation, and downgrade-barrier tests. They still do not authorize
a harness to inspect the storage version: unchanged v2 consumers must produce
the same result for v2, mixed, and fully migrated profiles.

Installed-artifact and host-boundary receipts are independently versioned exact
contracts in the same registry. They are encrypted readiness evidence, not
preflight extensions. A current artifact is rehashed from its retained wheel
and installed bytes; a host receipt is short-lived and bound to that artifact,
the preflight authority, profile, and scope. Neither contract authorizes a model
turn.

The authenticated backup manifest and its verified operator receipt are also
exact v1 contracts. Their authority bindings are optional only as values—the
fields are always present—so a backup made before or after host qualification
has one stable shape. Changing either field inventory requires a parallel
successor schema rather than an in-place parser change.

## Readiness surface

The RPC-only `capabilities_v1` action is emitted independently of preflight.
Its `local_production_ready` field is a conjunction, not a user-controlled
mode label. It stays false unless scoped authenticated storage, protected
semantic state, digest-bound Qwen3 embeddings, owner-only profile access,
immutable artifact evidence, verified backup and restore, qualified host
enforcement, qualified key custody, clean reconciliation/quarantine state, and
an explicit local-production selection all pass. Stable `EV-*` remediation
codes explain failed gates without exposing payloads, secrets, personal data,
or filesystem paths.

`production_ready` remains the separate attested-enclave class. Host-trusted
local production never claims hardware isolation, remote attestation, or
protection from a compromised host process. The two classes are mutually
exclusive. Shared Python, TypeScript, and JavaScript parsers reject impossible
class combinations, enclave claims attached to the local tier, incomplete
enclave claims, and ready-tier names when neither readiness boolean is true.

Host-boundary readiness is also caller-specific. A valid stored receipt must
match the invoking harness ID before it or the dependent backup/restore
evidence can be reported current. This diagnostic binding does not add fields
to, or change the behavior of, `preflight_v2`.
