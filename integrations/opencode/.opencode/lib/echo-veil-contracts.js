export const CANONICAL_PROFILE = "echo-universal-qwen3-v1"
export const MAX_CONTEXT_CHARS = 16_000
export const REQUIRED_PREFLIGHT_FAILURE =
  "Echo Veil required preflight is unavailable. The OpenCode model turn was blocked; no host memory fallback was used."
const CAPABILITIES_SCHEMA = "echo-veil-capabilities-v1"
const CAPABILITY_REQUIRED_FIELDS = [
  "artifact_verified",
  "at_rest_encrypted",
  "backup_verified",
  "embedding_identity_verified",
  "hardware_isolated",
  "host_boundary_verified",
  "host_compromise_protected",
  "implementation_healthy",
  "key_custody",
  "local_production_ready",
  "production_ready",
  "protection_tier",
  "remotely_attested",
  "restore_verified",
  "rollback_detection",
  "runtime_plaintext_exposure",
  "schema",
]
const CAPABILITY_OPTIONAL_FIELDS = new Set([
  "generated_at_ms",
  "limitations",
  "remediation_codes",
])
const CAPABILITY_TEXT_FIELDS = new Set([
  "key_custody",
  "protection_tier",
  "rollback_detection",
  "runtime_plaintext_exposure",
])

export function validateLegacyPreflight(value, querySource) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.preflight_ready !== true ||
    value.memory_authority !== "echo-veil" ||
    value.host !== "opencode" ||
    value.profile !== CANONICAL_PROFILE ||
    value.query_source !== querySource ||
    value.semantic !== true ||
    typeof value.context !== "string" ||
    value.context.length === 0 ||
    value.context.length > MAX_CONTEXT_CHARS ||
    !value.context.startsWith("ECHO VEIL REQUIRED MEMORY PREFLIGHT")
  ) {
    throw new Error(REQUIRED_PREFLIGHT_FAILURE)
  }
  return value.context
}

export function parseCapabilitiesV1(value) {
  if (value === null || value === undefined) return null
  if (Array.isArray(value) || typeof value !== "object") {
    throw new Error("Echo Veil capabilities_v1 response is invalid")
  }
  const required = new Set(CAPABILITY_REQUIRED_FIELDS)
  if (
    CAPABILITY_REQUIRED_FIELDS.some((field) => !Object.hasOwn(value, field)) ||
    Object.keys(value).some(
      (field) => !required.has(field) && !CAPABILITY_OPTIONAL_FIELDS.has(field),
    ) ||
    value.schema !== CAPABILITIES_SCHEMA
  ) {
    throw new Error("Echo Veil capabilities_v1 response is invalid")
  }
  for (const field of CAPABILITY_REQUIRED_FIELDS) {
    if (field === "schema") continue
    if (CAPABILITY_TEXT_FIELDS.has(field)) {
      if (
        typeof value[field] !== "string" ||
        !value[field] ||
        value[field].length > 256
      ) {
        throw new Error("Echo Veil capabilities_v1 response is invalid")
      }
    } else if (typeof value[field] !== "boolean") {
      throw new Error("Echo Veil capabilities_v1 response is invalid")
    }
  }
  if (
    Object.hasOwn(value, "generated_at_ms") &&
    (!Number.isSafeInteger(value.generated_at_ms) || value.generated_at_ms < 0)
  ) {
    throw new Error("Echo Veil capabilities_v1 response is invalid")
  }
  for (const field of ["limitations", "remediation_codes"]) {
    if (
      Object.hasOwn(value, field) &&
      (!Array.isArray(value[field]) ||
        value[field].length > 64 ||
        value[field].some(
          (item) => typeof item !== "string" || !item || item.length > 256,
        ))
    ) {
      throw new Error("Echo Veil capabilities_v1 response is invalid")
    }
  }
  const localReady = value.local_production_ready === true
  const enclaveReady = value.production_ready === true
  const commonReady = [
    "artifact_verified",
    "at_rest_encrypted",
    "backup_verified",
    "embedding_identity_verified",
    "host_boundary_verified",
    "implementation_healthy",
    "restore_verified",
  ].every((field) => value[field] === true)
  const remediationCodes = value.remediation_codes
  const noRemediations = remediationCodes === undefined ||
    (Array.isArray(remediationCodes) && remediationCodes.length === 0)
  let consistent = false
  if (!localReady || !enclaveReady) {
    if (localReady) {
      consistent = commonReady &&
        value.protection_tier === "host-trusted-local" &&
        value.runtime_plaintext_exposure === "transient-process-memory" &&
        value.key_custody === "macos-secure-enclave-v1" &&
        value.hardware_isolated === false &&
        value.remotely_attested === false &&
        value.host_compromise_protected === false &&
        noRemediations
    } else if (enclaveReady) {
      consistent = commonReady &&
        value.protection_tier === "attested-enclave" &&
        value.runtime_plaintext_exposure === "attested-enclave-boundary" &&
        typeof value.key_custody === "string" &&
        value.key_custody.startsWith("attested-") &&
        value.hardware_isolated === true &&
        value.remotely_attested === true &&
        value.host_compromise_protected === true &&
        noRemediations
    } else {
      consistent = value.protection_tier !== "host-trusted-local" &&
        value.protection_tier !== "attested-enclave" &&
        value.hardware_isolated === false &&
        value.remotely_attested === false &&
        value.host_compromise_protected === false
    }
  }
  if (!consistent) {
    throw new Error("Echo Veil capabilities_v1 response is inconsistent")
  }
  return value
}
