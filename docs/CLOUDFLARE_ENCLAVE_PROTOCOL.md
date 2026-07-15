# Cloudflare enclave gateway protocol

The Worker forwards five JSON endpoints unchanged. `/v1/attest` accepts
`nonce_b64` and returns `evidence_b64`. The signed normalized evidence must bind
the nonce, approved enclave measurement, sealed CKKS key, security level,
hardware/ZKP/homomorphic capability flags, expiry, and a 32-byte X25519
`transport_public_key_b64`.

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

- `/v1/challenge`: `{}` → `{ "challenge_b64": "..." }`
- `/v1/session`: `{ "proof_b64": "..." }` → `{ "session": "..." }`
- `/v1/vector/encrypt`: `{ "session": "...", "vector": [...] }` →
  `{ "ciphertext_b64": "..." }`
- `/v1/vector/similarity`: `{ "session": "...", "intent": [...],
  "ciphertext_b64": "..." }` → `{ "score": 0.0 }`

The origin must reject nonce reuse, expired sessions, invalid ZK proofs, wrong
dimensions, unbounded vectors, and any request whose mTLS client identity or
bearer credential is not approved.
