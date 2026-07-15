# Echo Veil Cloudflare enclave gateway

This Worker authenticates Echo Veil with Cloudflare Access and forwards the
five enclave protocol endpoints and an authenticated health check over a Worker
mTLS binding. After attestation,
request and response bodies are end-to-end AES-GCM envelopes derived from an
ephemeral X25519 exchange with the transport key bound into the enclave report,
so the Worker cannot read vectors, proofs, ciphertexts, or session tokens. It is a gateway;
the downstream SGX/SEV-SNP service remains responsible for CKKS, attestation,
sealed keys, session enforcement, and ZKP verification.

1. Apply `deploy/cloudflare` to create the Access application, posture rules,
   Service Auth policy, service token, and DNS-only origin record.
2. Export the real Access audience as `CF_ACCESS_AUD`.
3. Upload the enclave-origin client certificate with
   `npx wrangler mtls-certificate upload`, then set its certificate ID.
4. Store the origin bearer credential with
   `npx wrangler secret put ENCLAVE_ORIGIN_TOKEN`.
5. Export its ID as `CF_MTLS_CERTIFICATE_ID` and deploy with `npm run deploy`.
   The script generates an ignored config containing the
   `memory.algo-cli.com` custom domain and refuses missing bindings.

Do not proxy the mTLS enclave origin through Cloudflare: Worker mTLS bindings
currently require a non-proxied destination.

The enclave origin must implement the envelope protocol documented in
`docs/CLOUDFLARE_ENCLAVE_PROTOCOL.md`.
