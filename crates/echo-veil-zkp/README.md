# Echo Veil Ristretto255 proof gate

This crate implements a Schnorr proof of knowledge over the prime-order
Ristretto255 group. The proof transcript binds an enclave-issued random challenge
to the attested provider ID, approved image measurement, and CKKS key ID. The
enclave accepts only allowlisted public keys and consumes each challenge once.

Build and test:

```bash
cargo test --manifest-path crates/echo-veil-zkp/Cargo.toml
cargo build --release --manifest-path crates/echo-veil-zkp/Cargo.toml
```

Generate a client identity key without printing the secret:

```bash
echo-veil-zkp keygen --key-file /secure/path/echo-veil.identity
```

The key file is created with mode `0600` on Unix. Store or release the file from
the deployment secret manager; do not commit it. The JSON public key printed by
`keygen` is the value added to the enclave's public-key allowlist.

This proves possession of an allowlisted user key. It does not claim device
integrity. Operator device integrity is enforced separately by Cloudflare One
device posture; runtime service access uses Access Service Auth, mTLS, and this
proof gate.
