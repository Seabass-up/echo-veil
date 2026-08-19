# Algo-cli.com confidential deployment contract

This document covers the production enclave path. The local AES-GCM
agent-memory boundary, including plaintext-in-process and embedding-provider
limitations, is specified separately in
[`LOCAL_AGENT_SECURITY.md`](LOCAL_AGENT_SECURITY.md). Neither boundary implies
that unrelated host memory, wiki, graph, transcript, log, backup, or model
provider paths are protected.

## Trust paths

The production endpoint is `memory.algo-cli.com`. Cloudflare Access protects the
Worker, which forwards only the documented protocol to the DNS-only origin
`enclave-origin.algo-cli.com` over mTLS. The Worker also supplies a rotated
origin bearer secret. Post-attestation request bodies are encrypted end to end
to the X25519 key bound into enclave evidence, so the Worker cannot read vectors,
proofs, sessions, or CKKS ciphertexts.

There are two deliberately separate identity paths:

1. Human operator access uses the Cloudflare built-in identity provider, account
   membership, MFA, and Cloudflare One posture-only checks. It is used for
   administration and health/operations access.
2. Echo Veil runtime access uses a Cloudflare Access service token. It does not
   claim human or device posture. Runtime authorization additionally requires
   Worker-to-origin mTLS, the origin secret, and a one-time Ristretto255 Schnorr
   proof of an allowlisted client key.

## Confidential-compute root

The origin runs on an Azure `Standard_DC2as_v5` confidential VM in East US 2,
with AMD SEV-SNP, Secure Boot, vTPM, and confidential OS-disk encryption. Azure
Key Vault Premium Secure Key Release is the authority for the Ed25519
attestation-normalization key and transport secrets. A client trusts the
normalized envelope only after it independently verifies a fresh Microsoft
Azure Attestation JWT against a pinned issuer and offline JWKS. The native JWT
must bind the exact nonce/ephemeral-transport/workload runtime data through
SEV-SNP `reportdata`, the approved CCE policy through `hostdata`, the approved
MAA policy, a non-debuggable/non-migratable VM, and the approved launch
measurement. The Ed25519 signature alone can never make the deployment
production-ready.

The attestation signing key must never be copied into the image or source tree.
It is released only after Azure attestation satisfies the Key Vault release
policy. The approved measurement and public verification key are independently
distributed to Echo Veil clients.

## Cryptographic operation

OpenFHE CKKS uses the 128-bit classic security level. Anchor vectors are
normalized inside the confidential VM and encrypted with CKKS. Query vectors are
normalized inside the VM, multiplied with the encrypted anchor, homomorphically
summed, and only the scalar similarity is decrypted. CKKS ciphertexts are opaque
outside the VM. Key IDs are bound into evidence and archived payloads so a
restart under a different key fails rather than silently corrupting results.

The ZKP is a Schnorr proof of knowledge in the prime-order Ristretto255 group,
made non-interactive with a Merlin transcript. It binds the one-time random
challenge, provider ID, approved measurement, CKKS key ID, public key, and
commitment. Challenges expire, are consumed once, and cannot be replayed.

## Owners and release rule

- Accountable security owner: the Algo-cli Cloudflare account owner.
- Initial operations owner: the Algo-cli Cloudflare account owner.
- Production release requires an independent second reviewer who validates the
  measured image digest, Key Vault release policy, Access policy, mTLS chain,
  public-key allowlist, monitoring, and rollback evidence.

One person occupying both operational roles is accepted only for staging. It is
a production blocker until an independent reviewer is recorded.

## Fail-closed invariants

- The origin does not start without released signing/transport keys, an origin
  token, a non-empty ZKP public-key allowlist, persisted CKKS state, and an
  explicit approved measurement.
- The Worker does not deploy without a real Access audience and mTLS certificate
  binding generated into its ignored deployment configuration.
- The origin application binds only to loopback on the host; Caddy is the only
  public listener and overwrites the internal mTLS-verification header.
- Missing/expired Access assertions, bad mTLS, bad origin tokens, invalid or
  replayed envelopes, expired/consumed challenges, invalid sessions, wrong
  dimensions, and non-finite values are rejected.
- Access assertions and request/response streams are byte-bounded before they
  can be fully buffered. Worker-to-origin health and protocol requests have a
  fixed deadline, and upstream error bodies are not propagated to clients.
- Worker and Python transports handle redirects manually so Access service
  tokens, origin bearer credentials, and mTLS bindings are never forwarded to a
  redirect target.
- Successful origin responses must use JSON and match the documented endpoint
  envelope shape. Gateway errors include a generated request ID; structured
  logs contain fixed reason codes rather than assertions, secrets, or bodies.
- `enclave-origin.algo-cli.com` remains DNS-only. Proxying that hostname through
  Cloudflare would invalidate the Worker mTLS origin design.

## Local adapter availability boundary

The local staging adapter has a separate, non-production availability path for
an unavailable local Ollama service or configured model. It can read an existing
owner-only encrypted payload database and keyed term index, but it does not run
semantic embeddings, answerability verification, CKKS, enclave operations, or
the ZKP gate. Every response is marked degraded and read-only; writes,
promotion, inferential recall, reindexing, erasure, and lifecycle mutation are
disabled, including Live refresh. Returned records still require a valid record-bound encrypted
semantic-layer contract; missing or unauthenticated contracts stop the path.
Availability confidence is capped below the Coherent Assembly threshold.
A long-lived CLI/MCP process transitions to this mode if a later embedding
request detects a service outage; artifact-identity and malformed-response
failures do not activate it.
Both healthy and degraded recall authenticate the selected encrypted record
before its opaque topic token can support a bounded possible-conflict group.
The signal preserves competing records but never asserts semantic
incompatibility or chooses a winner.
This path does not satisfy or weaken any production invariant above and is not
used by the confidential origin.

Writable local profiles are process-serialized before live L1 is loaded. The
adapter validates both SQLite schemas and reconciles interrupted cross-database
operations at startup. Native host adapters pass only an explicit runtime
environment allowlist to the child process; production crypto keys, Access
credentials, and unrelated API tokens are not inherited.
Bundled MCP transports hold the writable lease only for one tool call, and the
Algo bridge holds it only for one memory operation. Sharing a local profile is
supported only inside one local-user authorization domain; a different user or
trust boundary requires a distinct profile.

Scoped-v2 local profiles additionally encrypt payloads, topics, lifecycle
anchors, retrieval vectors, and the complete four-layer semantic contract with
record/scope/schema/key-bound AES-GCM. The contract contains layer identity,
provenance, retention state, promotion history, and Contextual Logic links.
The adapter also enforces per-layer content bounds and rejects transcript-shaped
payloads outside temporary Live state without auto-summarizing or truncating
them. Unchanged Live refreshes renew only the encrypted contract; changed Live
content becomes a separately encrypted superseding record.
Layer filters are evaluated only after contract authentication. Bounded context
traces use confidence-checked logic roots and authenticate each outgoing linked
record; they do not materialize a plaintext graph or assign query confidence to
relationship evidence.
Temporal/supersession/operation fields, vector-row metadata, keyed lexical
terms, and the protected semantic contract are covered by a per-record,
domain-separated HMAC manifest. Authenticated deletion tombstones are verified
on every open and doctor check. The lifecycle SQLite store also uses a monotonic
generation compare-and-swap, so a second process cannot replace a newer L1
checkpoint with a stale snapshot. These controls detect row-level tampering and
stale writers; they do not prevent rollback of the entire database and keyring
to a mutually consistent older backup. Deployments that require anti-rollback
must add an external monotonic/version authority.
Keyed lexical tokens and opaque identifiers minimize the index but still expose
row counts, timestamps, vector dimensions, access patterns, and relationship
shape. Plaintext is present in the authorized Python and local embedding
processes. This remains a local staging control, not CKKS, hardware isolation,
or proof-gated production access.
