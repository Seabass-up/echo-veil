# Algo-cli.com deployment runbook

This runbook is ordered so no production trust claim is enabled before its
verification material exists.

> **Current enclave blocker:** do not complete a production promotion with the
> present origin until an externally pinned authenticated CKKS state manifest,
> public-key-derived key ID, verified parameter set, and startup
> encrypt/evaluate/decrypt self-test are implemented and independently reviewed.
> This runbook remains deployable staging guidance, not evidence that the
> blocker has been closed.

## 1. Build and review

1. Run the Python, Rust, Worker, Bicep, and OpenTofu validation commands from CI.
2. Build `deploy/enclave/Dockerfile` for `linux/amd64`, scan the resulting image,
   and publish it by immutable digest. The build performs a non-root OpenFHE
   import check and fails on an incompatible native wheel. Record the digest and
   software bill of materials.
3. Have the independent reviewer approve the threat model, the Ristretto proof
   protocol, OpenFHE parameters, image digest, and rollback procedure.

## 2. Azure confidential compute

1. Install Azure CLI and authenticate to the intended subscription.
2. Confirm `Standard_DC2as_v5` quota and availability in East US 2.
3. Create a resource group and deploy `deploy/azure/main.bicep` with an admin
   public key. Port 22 is not opened by the NSG.
4. Acquire the Azure guest-attestation JWT from the CVM. Confirm
   `sevsnpvm`, `azure-compliant-uvm`, `is-debuggable=false`, migration disabled,
   VMPL 0, Secure Boot, vTPM, and the expected 96-hex launch measurement.
5. Deploy `deploy/azure/skr-key.bicep` using the exact 96-character launch
   measurement. This creates an exportable RSA-HSM wrapping key whose release
   policy is bound to the East US 2 MAA authority and measurement.
6. Download only the RSA-HSM public key and encrypt the offline deployment
   directory with `scripts/secure_bundle.py wrap`. Copy the encrypted bundle—not
   the plaintext directory—to the VM.
7. Release the wrapping private key from the attested CVM and use
   `scripts/secure_bundle.py unwrap` to place the runtime-only files under
   `/run/echo-veil/secrets` with owner-only permissions. Never copy the
   attestation signing or transport private key into the image.
8. Initialize CKKS state once with `ECHO_VEIL_INITIALIZE_CKKS=1`; remove that
   variable and restart. Back up the encrypted confidential-disk state because
   changing CKKS key IDs intentionally invalidates older ciphertexts.
9. Keep the attestation identities distinct:
   `ECHO_VEIL_MEASUREMENT` is the 96-hex SEV-SNP launch measurement;
   `ECHO_VEIL_CCE_POLICY_HASH` is the 64-hex CCE policy hash carried in
   `hostdata`; `ECHO_VEIL_MAA_POLICY_HASH` is the approved MAA policy hash; and
   `ECHO_VEIL_WORKLOAD_DIGEST` is the reviewed immutable container/image
   workload digest. Never substitute the container digest for the launch
   measurement. Pin `ECHO_VEIL_IMAGE` by digest and make the CKKS directory
   owned by UID 10001 with mode `0700`.
10. Run the reviewed Azure attestation sidecar in the same network namespace,
    expose only its loopback `/attest/maa` endpoint, and set
    `ECHO_VEIL_MAA_SIDECAR_URL` plus the credential-free HTTPS
    `ECHO_VEIL_MAA_ENDPOINT`. Pin the sidecar image and configuration by digest.
11. Install Caddy with `deploy/enclave/Caddyfile`, install the mTLS CA, and start
   the compose service. The app port must remain bound to host loopback.

## 3. Cloudflare Zero Trust and DNS

1. Confirm or create the team domain `algo-cli.cloudflareaccess.com`, retain the
   built-in Cloudflare identity provider, and require account MFA.
2. Install Cloudflare One Client in Posture Only mode on operator devices.
3. Create a scoped API token with Access Apps/Policies Write, Access Service
   Tokens Write, Zero Trust Write, and `algo-cli.com` DNS edit permissions.
4. Apply `deploy/cloudflare`. Verify the origin A record is DNS-only.
5. Transfer the Access service-token credentials directly to the runtime secret
   manager. Do not use that token as evidence of operator device posture.
6. Upload the generated Worker mTLS client certificate with Wrangler. Install
   its issuing CA on Caddy. Put the matching origin token into the Worker secret.
7. Render and deploy the Worker using its real Access audience and mTLS
   certificate ID. Confirm `memory.algo-cli.com` is the Worker custom domain.

## 4. Configure Echo Veil

Construct `CloudflareEnclaveProvider` with `https://memory.algo-cli.com`, the
service-token credentials, `Ed25519AttestationVerifier` with the released public
key, approved launch measurement, CCE/MAA policy hashes, workload digest, and an
`AzureMaaJwtVerifier` built from the pinned MAA issuer plus an owner-only offline
JWKS file. Set the exact profile and scope on the provider. Also configure
`RistrettoSchnorrProofProvider.from_env()`. The Ristretto client key file must be
mode `0600`. Production startup is expected to fail if any evidence, key,
measurement, CKKS capability, or proof exchange is invalid.

## 5. Staging verification

Record evidence for every case:

- valid end-to-end protect/similarity round trip;
- wrong Access service token;
- operator without WARP, encrypted disk, or MFA;
- direct origin request without mTLS and without origin bearer token;
- unapproved and expired attestation;
- wrong attestation nonce or signing key;
- unknown Ristretto public key, modified proof, changed measurement, replayed or
  expired challenge;
- replayed AES-GCM envelope, expired session, dimension mismatch, zero/NaN/Inf
  vectors, oversized bodies, and malformed ciphertext;
- CKKS state restart and deliberate wrong-key-ID startup;
- origin outage and rollback to the previously approved image digest.

## 6. Production canary

Start with a single canary client, monitor Access denials, origin 4xx/5xx rates,
attestation expiry, session failures, latency, CPU/memory, disk, certificate and
service-token expiry. Rotate the origin token and service token once before full
release to prove the rotation procedure. Production promotion requires the
security owner, operations owner, and independent reviewer to sign the captured
verification report.
