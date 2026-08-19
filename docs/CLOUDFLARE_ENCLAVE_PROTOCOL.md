# Cloudflare enclave gateway protocol

The Worker forwards five JSON endpoints and an authenticated health check.
Request bodies are limited to 2 MiB while streaming; protocol responses are
limited to 16 MiB and health responses to 64 KiB. Origin calls have a fixed
10-second deadline. The Python transport also bounds responses and never
includes an upstream error body in an exception.
`/v1/attest` accepts
`nonce_b64` and returns `evidence_b64`. The signed normalized evidence must bind
the nonce, approved SEV-SNP launch measurement, CCE policy hash, MAA policy
hash, immutable workload digest, sealed CKKS key, security level,
hardware/ZKP/homomorphic capability flags, expiry, and a 32-byte X25519
`transport_public_key_b64`. It also carries a fresh Microsoft Azure Attestation
JWT and the exact canonical runtime data whose SHA-256 digest appears in the
SEV-SNP `reportdata` claim. Clients verify that JWT against an offline-pinned
MAA issuer/JWKS set; the origin's Ed25519 signature is normalization and
transport evidence, not a substitute for native attestation.

After local verification, every other request is an end-to-end envelope:

```json
{
  "ephemeral_public_key_b64": "...",
  "nonce_b64": "...",
  "ciphertext_b64": "..."
}
```

The client derives a 32-byte key with X25519 and HKDF-SHA256. HKDF uses the
12-byte request nonce as salt and the ASCII info
`echo-veil-cloudflare-envelope-v1:<path>`. The request uses AES-256-GCM with the
ASCII path as associated data. The response uses a fresh 12-byte nonce, the same
derived key, and `<path>:response` as associated data:

```json
{ "nonce_b64": "...", "ciphertext_b64": "..." }
```

Decrypted application payloads are:

- `/v1/challenge`: `{ "profile": "...", "scope": "..." }` →
  `{ "challenge_b64": "..." }`
- `/v1/session`: `{ "proof_b64": "...", "profile": "...", "scope": "..." }`
  → `{ "session": "..." }`
- `/v1/vector/encrypt`: `{ "session": "...", "vector": [...] }` →
  `{ "ciphertext_b64": "..." }`
- `/v1/vector/similarity`: `{ "session": "...", "intent": [...],
  "ciphertext_b64": "..." }` → `{ "score": 0.0 }`

The origin must reject nonce reuse, expired sessions, invalid ZK proofs, wrong
dimensions, unbounded vectors, and any request whose mTLS client identity or
bearer credential is not approved.

Each origin-created CKKS ciphertext is returned inside an
`echo-veil-authenticated-ckks-v1` wrapper. Its HMAC binds the ciphertext,
dimension, actual CKKS key ID, profile, scope, and verified Ristretto public
key. Similarity authenticates and checks that wrapper against the active
session before any native OpenFHE deserialization. A wrapper from another
client, profile, scope, key, or dimension is rejected.

The Ristretto proof is canonical JSON containing version, the issued challenge,
the allowlisted compressed public key, the compressed commitment, and the
canonical response scalar. Its Merlin transcript binds the provider ID,
measurement, CKKS key ID, challenge, public key, and commitment. The origin
consumes the challenge only after successful verification.

`GET /healthz` returns `ready`, `provider_id`, `key_id`, `platform`, `ckks`, and
`zkp`. It is not end-to-end enveloped, contains no secret values, and still
requires Access at the Worker plus Worker-to-origin mTLS and the origin bearer
token.

The gateway validates JSON content types and the documented top-level response
shape before forwarding a successful response. It creates a fresh
`X-Request-ID` for each request, includes it in the origin call and client
response, and never accepts a caller-supplied value as the trusted request ID.
