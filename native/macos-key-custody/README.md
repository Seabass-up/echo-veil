# macOS key-custody helper

This helper is the native boundary for Echo Veil's two macOS custody
providers:

- `macos-keychain-v1` stores the 32-byte root as a non-synchronizing,
  device-only Keychain item.
- `macos-secure-enclave-v1` creates a non-exportable P-256 key in the Secure
  Enclave and stores only an AES-GCM-wrapped root plus the opaque key reference
  in Keychain.

The helper never returns the root. It exposes only an exact, size-bounded local
protocol for v3 purpose-key derivation, root-authentication tags, health probes,
one-time import, and confirmed deletion. A `file-v1` profile must complete its
record-envelope v3 migration and a verified backup before import. The raw file
is retained until a separate verification and retirement step succeeds.

## Local boundary

The helper listens on a random Unix socket inside an owner-only profile
directory. It checks the peer UID and signed CDHash on every connection. The
Python client pins the helper's SHA-256 and signed CDHash, rechecks file identity
across launch, enforces five-second operation deadlines, and rejects unknown or
oversized messages. Keychain metadata binds the first importing peer CDHash to
the custody item.

This improves root-key custody and makes a copied profile insufficient to open
memory on another Mac. It does **not** isolate plaintext from malware or a
compromised process running as the same user. Derived, purpose-limited v3 keys
exist transiently in the trusted Python process, and ordinary memory plaintext
still exists there while it is used.

## Build and signing

```bash
swift build --package-path native/macos-key-custody -c release
codesign --verify --strict --verbose=2 \
  native/macos-key-custody/.build/release/echo-veil-key-custody
```

Swift produces a linker-signed ad-hoc binary for development. A release build
must be signed with the reviewed distribution identity, copied into the
immutable installed artifact, and recorded by exact SHA-256 and CDHash. The
profile descriptor pins those identities; changing either blocks key access and
requires an explicit, backup-protected helper re-enrollment.

Do not add payload logging, a network listener, root export, version-2 root-key
derivation, an unbounded message, or a code-signature bypass.
