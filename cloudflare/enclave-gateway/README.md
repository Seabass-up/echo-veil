# Echo Veil Cloudflare enclave gateway

This Worker authenticates Echo Veil with Cloudflare Access and forwards the
five enclave protocol endpoints over a Worker mTLS binding. After attestation,
request and response bodies are end-to-end AES-GCM envelopes derived from an
ephemeral X25519 exchange with the transport key bound into the enclave report,
so the Worker cannot read vectors, proofs, ciphertexts, or session tokens. It is a gateway;
the downstream SGX/SEV-SNP service remains responsible for CKKS, attestation,
sealed keys, session enforcement, and ZKP verification.

1. Create a Cloudflare Access application for the Worker and a Service Auth
   policy containing an Access service token.
2. Replace `TEAM_DOMAIN`, `POLICY_AUD`, and `ENCLAVE_ORIGIN` in `wrangler.jsonc`.
3. Upload the enclave-origin client certificate with
   `npx wrangler mtls-certificate upload`, then set its certificate ID.
4. Store the origin bearer credential with
   `npx wrangler secret put ENCLAVE_ORIGIN_TOKEN`.
5. Configure a Worker custom domain and deploy with `npm run deploy`.

Do not proxy the mTLS enclave origin through Cloudflare: Worker mTLS bindings
currently require a non-proxied destination.

The enclave origin must implement the envelope protocol documented in
`docs/CLOUDFLARE_ENCLAVE_PROTOCOL.md`.
