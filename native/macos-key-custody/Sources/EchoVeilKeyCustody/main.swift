import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

private let requestSchema = "echo-veil-key-custody-request-v1"
private let responseSchema = "echo-veil-key-custody-response-v1"
private let service = "com.algo-cli.echo-veil.key-custody.v1"
private let maximumMessageBytes = 1_048_576
private let maximumAuthenticationBytes = 65_536
private let socketTimeoutSeconds = 5

private enum HelperError: Error {
  case coded(String)
}

private struct Metadata: Codable {
  let schema: String
  let provider: String
  let reference: String
  let keyID: String
  let peerCDHash: String
}

private struct WrappedRoot: Codable {
  let schema: String
  let ephemeralPublicKey: String
  let sealedRoot: String
}

private func coded(_ code: String) -> HelperError {
  HelperError.coded(code)
}

private func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
  let left = Array(lhs.utf8)
  let right = Array(rhs.utf8)
  guard left.count == right.count else { return false }
  var difference: UInt8 = 0
  for index in left.indices {
    difference |= left[index] ^ right[index]
  }
  return difference == 0
}

private func hex(_ bytes: some Sequence<UInt8>) -> String {
  bytes.map { String(format: "%02x", $0) }.joined()
}

private func keyID(for root: Data) -> String {
  var material = Data("echo-veil-key-id-v1\0".utf8)
  material.append(root)
  return "ev-" + hex(SHA256.hash(data: material)).prefix(16)
}

private func canonicalBase64(_ data: Data) -> String {
  data.base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
}

private func decodeBase64(_ value: Any?, maximum: Int) throws -> Data {
  guard let text = value as? String, !text.isEmpty, text.count <= maximum * 2 + 8 else {
    throw coded("EVKC-INVALID-BASE64")
  }
  var standard = text.replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/")
  while standard.count % 4 != 0 { standard.append("=") }
  guard let decoded = Data(base64Encoded: standard, options: []),
    decoded.count <= maximum,
    canonicalBase64(decoded) == text
  else {
    throw coded("EVKC-INVALID-BASE64")
  }
  return decoded
}

private func privateKeychainQuery(account: String) -> [String: Any] {
  [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: account,
    kSecAttrSynchronizable as String: false,
  ]
}

private func keychainAdd(account: String, data: Data) throws {
  var query = privateKeychainQuery(account: account)
  query[kSecValueData as String] = data
  query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
  let status = SecItemAdd(query as CFDictionary, nil)
  guard status == errSecSuccess else {
    throw coded(status == errSecDuplicateItem ? "EVKC-ITEM-EXISTS" : "EVKC-KEYCHAIN-WRITE")
  }
}

private func keychainRead(account: String, maximum: Int) throws -> Data {
  var query = privateKeychainQuery(account: account)
  query[kSecReturnData as String] = true
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  var result: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &result)
  guard status == errSecSuccess, let data = result as? Data, data.count <= maximum else {
    throw coded(status == errSecItemNotFound ? "EVKC-ITEM-MISSING" : "EVKC-KEYCHAIN-READ")
  }
  return data
}

private func keychainDelete(account: String) throws {
  let status = SecItemDelete(privateKeychainQuery(account: account) as CFDictionary)
  guard status == errSecSuccess || status == errSecItemNotFound else {
    throw coded("EVKC-KEYCHAIN-DELETE")
  }
}

private func keychainReplace(account: String, data: Data) throws {
  let update = [kSecValueData as String: data]
  let status = SecItemUpdate(
    privateKeychainQuery(account: account) as CFDictionary,
    update as CFDictionary
  )
  guard status == errSecSuccess else { throw coded("EVKC-KEYCHAIN-WRITE") }
}

private func account(_ reference: String, _ suffix: String) -> String {
  reference + "." + suffix
}

private func metadata(for reference: String) throws -> Metadata {
  let data = try keychainRead(account: account(reference, "metadata"), maximum: 4_096)
  let decoded = try JSONDecoder().decode(Metadata.self, from: data)
  guard decoded.schema == "echo-veil-key-custody-metadata-v1",
    decoded.reference == reference,
    ["macos-keychain-v1", "macos-secure-enclave-v1"].contains(decoded.provider),
    decoded.keyID.range(of: #"^ev-[0-9a-f]{16}$"#, options: .regularExpression) != nil,
    decoded.peerCDHash.range(of: #"^[0-9a-f]{40}$"#, options: .regularExpression) != nil
  else {
    throw coded("EVKC-METADATA-INVALID")
  }
  return decoded
}

private func secureEnclaveWrappingKey(reference: String) throws
  -> SecureEnclave.P256.KeyAgreement.PrivateKey
{
  let representation = try keychainRead(
    account: account(reference, "secure-enclave-key"),
    maximum: 4_096
  )
  do {
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: representation)
  } catch {
    throw coded("EVKC-SECURE-ENCLAVE-KEY")
  }
}

private func wrapRoot(_ root: Data, reference: String) throws -> (Data, Data) {
  var accessError: Unmanaged<CFError>?
  guard
    let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      [.privateKeyUsage],
      &accessError
    )
  else {
    throw coded("EVKC-ACCESS-CONTROL")
  }
  let enclaveKey: SecureEnclave.P256.KeyAgreement.PrivateKey
  do {
    enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
  } catch {
    throw coded("EVKC-SECURE-ENCLAVE-UNAVAILABLE")
  }
  let ephemeral = P256.KeyAgreement.PrivateKey()
  let shared: SharedSecret
  do {
    shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
  } catch {
    throw coded("EVKC-KEY-AGREEMENT")
  }
  let wrappingKey = shared.hkdfDerivedSymmetricKey(
    using: SHA256.self,
    salt: Data(SHA256.hash(data: Data(reference.utf8))),
    sharedInfo: Data("echo-veil-secure-enclave-wrap-v1\0".utf8) + Data(reference.utf8),
    outputByteCount: 32
  )
  let sealed: AES.GCM.SealedBox
  do {
    sealed = try AES.GCM.seal(root, using: wrappingKey)
  } catch {
    throw coded("EVKC-WRAP-FAILED")
  }
  guard let combined = sealed.combined else {
    throw coded("EVKC-WRAP-FAILED")
  }
  let wrapped = WrappedRoot(
    schema: "echo-veil-secure-enclave-wrap-v1",
    ephemeralPublicKey: canonicalBase64(ephemeral.publicKey.x963Representation),
    sealedRoot: canonicalBase64(combined)
  )
  return (enclaveKey.dataRepresentation, try JSONEncoder().encode(wrapped))
}

private func unwrapRoot(reference: String) throws -> Data {
  let envelopeData = try keychainRead(account: account(reference, "wrapped-root"), maximum: 4_096)
  let envelope = try JSONDecoder().decode(WrappedRoot.self, from: envelopeData)
  guard envelope.schema == "echo-veil-secure-enclave-wrap-v1" else {
    throw coded("EVKC-WRAP-INVALID")
  }
  let publicData = try decodeBase64(envelope.ephemeralPublicKey, maximum: 256)
  let sealedData = try decodeBase64(envelope.sealedRoot, maximum: 256)
  let publicKey: P256.KeyAgreement.PublicKey
  let sealedBox: AES.GCM.SealedBox
  do {
    publicKey = try P256.KeyAgreement.PublicKey(x963Representation: publicData)
    sealedBox = try AES.GCM.SealedBox(combined: sealedData)
  } catch {
    throw coded("EVKC-WRAP-INVALID")
  }
  let enclaveKey = try secureEnclaveWrappingKey(reference: reference)
  let shared: SharedSecret
  do {
    shared = try enclaveKey.sharedSecretFromKeyAgreement(with: publicKey)
  } catch {
    throw coded("EVKC-KEY-AGREEMENT")
  }
  let wrappingKey = shared.hkdfDerivedSymmetricKey(
    using: SHA256.self,
    salt: Data(SHA256.hash(data: Data(reference.utf8))),
    sharedInfo: Data("echo-veil-secure-enclave-wrap-v1\0".utf8) + Data(reference.utf8),
    outputByteCount: 32
  )
  do {
    let root = try AES.GCM.open(sealedBox, using: wrappingKey)
    guard root.count == 32 else { throw coded("EVKC-ROOT-INVALID") }
    return root
  } catch let error as HelperError {
    throw error
  } catch {
    throw coded("EVKC-UNWRAP-FAILED")
  }
}

private func loadRoot(_ metadata: Metadata) throws -> Data {
  let root: Data
  if metadata.provider == "macos-keychain-v1" {
    root = try keychainRead(account: account(metadata.reference, "root"), maximum: 32)
  } else {
    root = try unwrapRoot(reference: metadata.reference)
  }
  guard root.count == 32, constantTimeEqual(keyID(for: root), metadata.keyID) else {
    throw coded("EVKC-ROOT-BINDING")
  }
  return root
}

private func importRoot(
  root: Data,
  provider: String,
  reference: String,
  peerCDHash: String
) throws -> String {
  guard root.count == 32 else { throw coded("EVKC-ROOT-INVALID") }
  guard ["macos-keychain-v1", "macos-secure-enclave-v1"].contains(provider) else {
    throw coded("EVKC-PROVIDER-UNSUPPORTED")
  }
  do {
    _ = try metadata(for: reference)
    throw coded("EVKC-ITEM-EXISTS")
  } catch HelperError.coded(let code) where code == "EVKC-ITEM-MISSING" {
    // Expected for a new reference.
  }
  let identifier = keyID(for: root)
  var created: [String] = []
  do {
    if provider == "macos-keychain-v1" {
      try keychainAdd(account: account(reference, "root"), data: root)
      created.append(account(reference, "root"))
    } else {
      let (keyRepresentation, wrapped) = try wrapRoot(root, reference: reference)
      try keychainAdd(
        account: account(reference, "secure-enclave-key"),
        data: keyRepresentation
      )
      created.append(account(reference, "secure-enclave-key"))
      try keychainAdd(account: account(reference, "wrapped-root"), data: wrapped)
      created.append(account(reference, "wrapped-root"))
    }
    let item = Metadata(
      schema: "echo-veil-key-custody-metadata-v1",
      provider: provider,
      reference: reference,
      keyID: identifier,
      peerCDHash: peerCDHash
    )
    try keychainAdd(
      account: account(reference, "metadata"),
      data: try JSONEncoder().encode(item)
    )
    created.append(account(reference, "metadata"))
    var zero = UInt64(0).bigEndian
    try keychainAdd(
      account: account(reference, "generation"),
      data: Data(bytes: &zero, count: MemoryLayout<UInt64>.size)
    )
    created.append(account(reference, "generation"))
  } catch {
    for name in created.reversed() { try? keychainDelete(account: name) }
    throw error
  }
  return identifier
}

private func portableKey(recoveryKey: Data, context: Data) throws -> SymmetricKey {
  guard recoveryKey.count == 32, !context.isEmpty, context.count <= 4_096 else {
    throw coded("EVKC-PORTABLE-CONTEXT")
  }
  return HKDF<SHA256>.deriveKey(
    inputKeyMaterial: SymmetricKey(data: recoveryKey),
    salt: Data(SHA256.hash(data: context)),
    info: Data("echo-veil-portable-root-v1\0".utf8) + context,
    outputByteCount: 32
  )
}

private func exportPortable(root: Data, recoveryKey: Data, context: Data) throws -> Data {
  do {
    let sealed = try AES.GCM.seal(
      root,
      using: portableKey(recoveryKey: recoveryKey, context: context),
      authenticating: context
    )
    guard let combined = sealed.combined else { throw coded("EVKC-PORTABLE-WRAP") }
    return combined
  } catch let error as HelperError {
    throw error
  } catch {
    throw coded("EVKC-PORTABLE-WRAP")
  }
}

private func importPortable(envelope: Data, recoveryKey: Data, context: Data) throws -> Data {
  guard envelope.count >= 48, envelope.count <= 256 else {
    throw coded("EVKC-PORTABLE-ENVELOPE")
  }
  do {
    let box = try AES.GCM.SealedBox(combined: envelope)
    let root = try AES.GCM.open(
      box,
      using: portableKey(recoveryKey: recoveryKey, context: context),
      authenticating: context
    )
    guard root.count == 32 else { throw coded("EVKC-ROOT-INVALID") }
    return root
  } catch let error as HelperError {
    throw error
  } catch {
    throw coded("EVKC-PORTABLE-AUTH")
  }
}

private func generation(reference: String) throws -> UInt64 {
  do {
    let data = try keychainRead(
      account: account(reference, "generation"),
      maximum: MemoryLayout<UInt64>.size
    )
    guard data.count == MemoryLayout<UInt64>.size else {
      throw coded("EVKC-GENERATION-INVALID")
    }
    return data.withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(as: UInt64.self)) }
  } catch HelperError.coded(let code) where code == "EVKC-ITEM-MISSING" {
    return 0
  }
}

private func advanceGeneration(reference: String, expected: UInt64, new: UInt64) throws -> UInt64 {
  let current = try generation(reference: reference)
  guard current == expected, new == expected + 1 else {
    throw coded("EVKC-GENERATION-CONFLICT")
  }
  var encoded = new.bigEndian
  let data = Data(bytes: &encoded, count: MemoryLayout<UInt64>.size)
  do {
    try keychainReplace(account: account(reference, "generation"), data: data)
  } catch HelperError.coded(let code) where code == "EVKC-KEYCHAIN-WRITE" && current == 0 {
    try keychainAdd(account: account(reference, "generation"), data: data)
  }
  return new
}

private func deriveV3Key(root: Data, request: [String: Any]) throws -> Data {
  guard request["algorithm"] as? String == "HKDF-SHA256/AES-256-GCM",
    request["envelope_version"] as? Int == 3,
    let keyEpoch = request["key_epoch"] as? Int,
    (1...Int(Int32.max)).contains(keyEpoch),
    let profileScope = request["profile_scope"] as? String,
    !profileScope.isEmpty,
    profileScope.count <= 256,
    let scopeID = request["scope_id"] as? String,
    scopeID.range(of: #"^scope-[0-9a-f]{32}$"#, options: .regularExpression) != nil,
    let purpose = request["purpose"] as? String,
    [
      "payload-encryption", "vector-encryption", "semantic-contract-encryption",
      "topic-token", "lexical-token", "content-digest",
      "record-integrity-authentication", "tombstone-authentication",
      "lsh-projection-index-token", "preflight-signing-key-protection",
      "backup-manifest-authentication",
    ].contains(purpose)
  else {
    throw coded("EVKC-DERIVATION-CONTEXT")
  }
  let context: [String: Any] = [
    "algorithm": "HKDF-SHA256/AES-256-GCM",
    "envelope_version": 3,
    "key_epoch": keyEpoch,
    "profile_scope": profileScope,
    "purpose": purpose,
    "scope_id": scopeID,
  ]
  let contextData = try JSONSerialization.data(
    withJSONObject: context,
    options: [.sortedKeys, .withoutEscapingSlashes]
  )
  var saltInput = Data("echo-veil-record-envelope-v3-salt\0".utf8)
  saltInput.append(Data(scopeID.utf8))
  let salt = Data(SHA256.hash(data: saltInput))
  var info = Data("echo-veil-record-envelope-v3\0".utf8)
  info.append(contextData)
  let key = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: SymmetricKey(data: root),
    salt: salt,
    info: info,
    outputByteCount: 32
  )
  return key.withUnsafeBytes { Data($0) }
}

private func rootHMAC(root: Data, message: Data) -> Data {
  Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: root)))
}

private func peerIdentity(_ descriptor: Int32) throws -> (uid_t, pid_t, String) {
  var uid: uid_t = 0
  var gid: gid_t = 0
  guard getpeereid(descriptor, &uid, &gid) == 0, uid == getuid() else {
    throw coded("EVKC-PEER-UID")
  }
  var pid: pid_t = 0
  var length = socklen_t(MemoryLayout<pid_t>.size)
  guard getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) == 0, pid > 0 else {
    throw coded("EVKC-PEER-PID")
  }
  let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
  var code: SecCode?
  guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
    let code
  else {
    throw coded("EVKC-PEER-CODE")
  }
  var staticCode: SecStaticCode?
  guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
    let staticCode
  else {
    throw coded("EVKC-PEER-CODE")
  }
  var information: CFDictionary?
  guard
    SecCodeCopySigningInformation(
      staticCode,
      SecCSFlags(rawValue: kSecCSSigningInformation),
      &information
    ) == errSecSuccess,
    let dictionary = information as? [String: Any],
    let unique = dictionary[kSecCodeInfoUnique as String] as? Data,
    unique.count == 20
  else {
    throw coded("EVKC-PEER-CODE")
  }
  return (uid, pid, hex(unique))
}

private func readExact(_ descriptor: Int32, count: Int) throws -> Data {
  var output = Data(count: count)
  var offset = 0
  let result: Bool = output.withUnsafeMutableBytes { bytes in
    guard let base = bytes.baseAddress else { return false }
    while offset < count {
      let amount = Darwin.read(descriptor, base.advanced(by: offset), count - offset)
      if amount <= 0 { return false }
      offset += amount
    }
    return true
  }
  guard result else { throw coded("EVKC-TRANSPORT-READ") }
  return output
}

private func writeAll(_ descriptor: Int32, data: Data) throws {
  var offset = 0
  let result: Bool = data.withUnsafeBytes { bytes in
    guard let base = bytes.baseAddress else { return false }
    while offset < data.count {
      let amount = Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
      if amount <= 0 { return false }
      offset += amount
    }
    return true
  }
  guard result else { throw coded("EVKC-TRANSPORT-WRITE") }
}

private func exactFields(_ request: [String: Any], _ fields: Set<String>) throws {
  guard Set(request.keys) == fields else { throw coded("EVKC-REQUEST-FIELDS") }
}

private func processRequest(_ request: [String: Any], peerCDHash: String) throws -> [String: Any] {
  guard request["schema"] as? String == requestSchema,
    let requestID = request["request_id"] as? String,
    requestID.range(of: #"^[0-9a-f]{32}$"#, options: .regularExpression) != nil,
    let operation = request["operation"] as? String,
    let provider = request["provider"] as? String,
    let reference = request["reference"] as? String,
    reference.range(of: #"^evkc-[0-9a-f]{32}$"#, options: .regularExpression) != nil
  else {
    throw coded("EVKC-REQUEST-INVALID")
  }
  let common: Set<String> = ["schema", "request_id", "operation", "provider", "reference"]
  if operation == "import-root" {
    try exactFields(request, common.union(["root_b64"]))
    var root = try decodeBase64(request["root_b64"], maximum: 32)
    defer { root.resetBytes(in: 0..<root.count) }
    let identifier = try importRoot(
      root: root,
      provider: provider,
      reference: reference,
      peerCDHash: peerCDHash
    )
    return ["key_id": identifier]
  }
  if operation == "import-portable" {
    try exactFields(
      request,
      common.union(["context_b64", "envelope_b64", "recovery_key_b64"])
    )
    var recoveryKey = try decodeBase64(request["recovery_key_b64"], maximum: 32)
    defer { recoveryKey.resetBytes(in: 0..<recoveryKey.count) }
    let context = try decodeBase64(request["context_b64"], maximum: 4_096)
    let envelope = try decodeBase64(request["envelope_b64"], maximum: 256)
    var root = try importPortable(
      envelope: envelope,
      recoveryKey: recoveryKey,
      context: context
    )
    defer { root.resetBytes(in: 0..<root.count) }
    let identifier = try importRoot(
      root: root,
      provider: provider,
      reference: reference,
      peerCDHash: peerCDHash
    )
    return ["key_id": identifier]
  }

  let item = try metadata(for: reference)
  guard item.provider == provider, constantTimeEqual(item.peerCDHash, peerCDHash) else {
    throw coded("EVKC-PEER-BINDING")
  }
  if operation == "probe" {
    try exactFields(request, common)
    var root = try loadRoot(item)
    defer { root.resetBytes(in: 0..<root.count) }
    return ["key_id": item.keyID, "provider": item.provider, "reference": item.reference]
  }
  if operation == "derive-v3-key" {
    try exactFields(
      request,
      common.union([
        "algorithm", "envelope_version", "key_epoch", "profile_scope",
        "purpose", "scope_id",
      ])
    )
    var root = try loadRoot(item)
    defer { root.resetBytes(in: 0..<root.count) }
    var derived = try deriveV3Key(root: root, request: request)
    defer { derived.resetBytes(in: 0..<derived.count) }
    return ["key_b64": canonicalBase64(derived)]
  }
  if operation == "root-hmac" {
    try exactFields(request, common.union(["message_b64"]))
    let message = try decodeBase64(request["message_b64"], maximum: maximumAuthenticationBytes)
    var root = try loadRoot(item)
    defer { root.resetBytes(in: 0..<root.count) }
    return ["tag_b64": canonicalBase64(rootHMAC(root: root, message: message))]
  }
  if operation == "export-portable" {
    try exactFields(
      request,
      common.union(["context_b64", "recovery_key_b64"])
    )
    var recoveryKey = try decodeBase64(request["recovery_key_b64"], maximum: 32)
    defer { recoveryKey.resetBytes(in: 0..<recoveryKey.count) }
    let context = try decodeBase64(request["context_b64"], maximum: 4_096)
    var root = try loadRoot(item)
    defer { root.resetBytes(in: 0..<root.count) }
    let envelope = try exportPortable(
      root: root,
      recoveryKey: recoveryKey,
      context: context
    )
    return ["envelope_b64": canonicalBase64(envelope)]
  }
  if operation == "generation" {
    try exactFields(request, common)
    let current = try generation(reference: reference)
    guard current <= UInt64(Int.max) else { throw coded("EVKC-GENERATION-INVALID") }
    return ["generation": Int(current)]
  }
  if operation == "advance-generation" {
    try exactFields(
      request,
      common.union(["expected_generation", "new_generation"])
    )
    guard let expected = request["expected_generation"] as? Int,
      let new = request["new_generation"] as? Int,
      expected >= 0,
      new >= 0
    else {
      throw coded("EVKC-GENERATION-INVALID")
    }
    let current = try advanceGeneration(
      reference: reference,
      expected: UInt64(expected),
      new: UInt64(new)
    )
    return ["generation": Int(current)]
  }
  if operation == "delete" {
    try exactFields(request, common.union(["confirm"]))
    guard request["confirm"] as? Bool == true else { throw coded("EVKC-CONFIRM-REQUIRED") }
    try keychainDelete(account: account(reference, "metadata"))
    try keychainDelete(account: account(reference, "root"))
    try keychainDelete(account: account(reference, "wrapped-root"))
    try keychainDelete(account: account(reference, "secure-enclave-key"))
    try keychainDelete(account: account(reference, "generation"))
    return [:]
  }
  throw coded("EVKC-OPERATION-UNSUPPORTED")
}

private func response(requestID: String, result: [String: Any]?, error: String?) throws -> Data {
  let object: [String: Any] = [
    "schema": responseSchema,
    "request_id": requestID,
    "ok": error == nil,
    "result": result ?? [:],
    "error": error ?? NSNull(),
  ]
  return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

private func handleClient(_ descriptor: Int32) {
  defer { Darwin.close(descriptor) }
  var timeout = timeval(tv_sec: socketTimeoutSeconds, tv_usec: 0)
  _ = withUnsafePointer(to: &timeout) {
    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
  }
  _ = withUnsafePointer(to: &timeout) {
    setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
  }
  let peer: (uid_t, pid_t, String)
  do {
    peer = try peerIdentity(descriptor)
  } catch {
    return
  }
  while true {
    do {
      let header = try readExact(descriptor, count: 4)
      let size = header.withUnsafeBytes {
        UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
      }
      guard size > 0, size <= maximumMessageBytes else { return }
      let body = try readExact(descriptor, count: Int(size))
      guard let object = try JSONSerialization.jsonObject(with: body) as? [String: Any] else {
        return
      }
      let requestID = object["request_id"] as? String ?? "00000000000000000000000000000000"
      let payload: Data
      do {
        payload = try response(
          requestID: requestID,
          result: processRequest(object, peerCDHash: peer.2),
          error: nil
        )
      } catch HelperError.coded(let code) {
        payload = try response(requestID: requestID, result: nil, error: code)
      } catch {
        payload = try response(requestID: requestID, result: nil, error: "EVKC-INTERNAL")
      }
      var length = UInt32(payload.count).bigEndian
      let lengthData = Data(bytes: &length, count: 4)
      try writeAll(descriptor, data: lengthData + payload)
    } catch {
      return
    }
  }
}

private func validateSocketParent(_ path: String) throws {
  let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
  var information = stat()
  guard lstat(parent, &information) == 0,
    (information.st_mode & S_IFMT) == S_IFDIR,
    information.st_uid == getuid(),
    (information.st_mode & 0o077) == 0
  else {
    throw coded("EVKC-SOCKET-PARENT")
  }
}

private func serve(socketPath: String) throws -> Never {
  guard !socketPath.isEmpty, socketPath.utf8.count < 100 else {
    throw coded("EVKC-SOCKET-PATH")
  }
  try validateSocketParent(socketPath)
  var existing = stat()
  guard lstat(socketPath, &existing) != 0, errno == ENOENT else {
    throw coded("EVKC-SOCKET-EXISTS")
  }
  let listener = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
  guard listener >= 0 else { throw coded("EVKC-SOCKET-CREATE") }
  defer {
    Darwin.close(listener)
    unlink(socketPath)
  }
  var address = sockaddr_un()
  address.sun_family = sa_family_t(AF_UNIX)
  address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
  let bytes = Array(socketPath.utf8CString)
  withUnsafeMutablePointer(to: &address.sun_path) { pointer in
    pointer.withMemoryRebound(to: CChar.self, capacity: bytes.count) { destination in
      for index in bytes.indices { destination[index] = bytes[index] }
    }
  }
  let bound = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
      Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
  }
  guard bound == 0, chmod(socketPath, 0o600) == 0, Darwin.listen(listener, 4) == 0 else {
    throw coded("EVKC-SOCKET-BIND")
  }
  while true {
    let client = Darwin.accept(listener, nil, nil)
    if client < 0 {
      if errno == EINTR { continue }
      throw coded("EVKC-SOCKET-ACCEPT")
    }
    handleClient(client)
  }
}

private func main() -> Int32 {
  let arguments = CommandLine.arguments
  guard arguments.count == 4, arguments[1] == "serve", arguments[2] == "--socket" else {
    return 64
  }
  do {
    try serve(socketPath: arguments[3])
  } catch {
    // Deliberately payload-free. Detailed failures are returned as stable codes
    // after a peer-authenticated connection exists.
    return 70
  }
}

exit(main())
