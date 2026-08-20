import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalJson } from "./preflight.js";

const RECEIPT_SCHEMA = "echo-veil-pi-artifact-v1";
const EXPECTED_HOST_VERSION = "0.84.2";
const EXPECTED_PACKAGE_VERSION = "0.7.0";
const MAX_ARTIFACT_BYTES = 2_000_000;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const EXPECTED_FILES = [
  "extensions/index.ts",
  "package-lock.json",
  "package.json",
  "src/artifact.ts",
  "src/preflight.ts",
  "src/runner.ts",
] as const;

type ArtifactReceipt = {
  artifact_authority_id: string;
  files: Record<string, string>;
  host: "pi";
  host_version: string;
  package: "pi-extension-echo-veil";
  package_version: string;
  schema: typeof RECEIPT_SCHEMA;
};

function digest(value: Buffer | string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function readRegularFile(path: string): Buffer {
  const descriptor = openSync(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const before = fstatSync(descriptor);
    const getuid = process.getuid;
    if (
      !before.isFile() ||
      before.size > MAX_ARTIFACT_BYTES ||
      (before.mode & 0o022) !== 0 ||
      (getuid !== undefined && before.uid !== getuid())
    ) {
      throw new Error("Pi artifact file is unsafe");
    }
    const value = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (
      value.length !== before.size ||
      after.size !== before.size ||
      after.ino !== before.ino ||
      after.dev !== before.dev
    ) {
      throw new Error("Pi artifact changed while it was being verified");
    }
    return value;
  } finally {
    closeSync(descriptor);
  }
}

function parseReceipt(value: Buffer): ArtifactReceipt {
  const decoded: unknown = JSON.parse(value.toString("utf8"));
  if (decoded === null || Array.isArray(decoded) || typeof decoded !== "object") {
    throw new Error("Pi artifact receipt is invalid");
  }
  const receipt = decoded as Record<string, unknown>;
  const keys = Object.keys(receipt).sort();
  const expectedKeys = [
    "artifact_authority_id",
    "files",
    "host",
    "host_version",
    "package",
    "package_version",
    "schema",
  ].sort();
  if (
    canonicalJson(keys) !== canonicalJson(expectedKeys) ||
    receipt.schema !== RECEIPT_SCHEMA ||
    receipt.host !== "pi" ||
    receipt.package !== "pi-extension-echo-veil" ||
    receipt.host_version !== EXPECTED_HOST_VERSION ||
    receipt.package_version !== EXPECTED_PACKAGE_VERSION ||
    typeof receipt.artifact_authority_id !== "string" ||
    !DIGEST.test(receipt.artifact_authority_id) ||
    receipt.files === null ||
    Array.isArray(receipt.files) ||
    typeof receipt.files !== "object"
  ) {
    throw new Error("Pi artifact receipt is invalid");
  }
  return receipt as ArtifactReceipt;
}

export function loadPiArtifactAuthority(
  expectedAuthorityId = process.env.ECHO_VEIL_PI_ARTIFACT_AUTHORITY_ID,
): ArtifactReceipt {
  const integrationRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  return verifyPiArtifactDirectory(integrationRoot, expectedAuthorityId);
}

export function verifyPiArtifactDirectory(
  integrationRoot: string,
  expectedAuthorityId: string | undefined,
): ArtifactReceipt {
  if (typeof expectedAuthorityId !== "string" || !DIGEST.test(expectedAuthorityId)) {
    throw new Error("Pi artifact authority is not explicitly pinned");
  }
  const root = resolve(integrationRoot);
  const rootDetails = lstatSync(root);
  const getuid = process.getuid;
  if (
    !rootDetails.isDirectory() ||
    rootDetails.isSymbolicLink() ||
    (rootDetails.mode & 0o022) !== 0 ||
    (getuid !== undefined && rootDetails.uid !== getuid())
  ) {
    throw new Error("Pi artifact directory is unsafe");
  }
  const receipt = parseReceipt(
    readRegularFile(resolve(root, "artifact-receipt.json")),
  );
  const fileNames = Object.keys(receipt.files).sort();
  if (canonicalJson(fileNames) !== canonicalJson([...EXPECTED_FILES].sort())) {
    throw new Error("Pi artifact receipt file set is invalid");
  }
  for (const name of EXPECTED_FILES) {
    const expected = receipt.files[name];
    if (typeof expected !== "string" || !DIGEST.test(expected)) {
      throw new Error("Pi artifact file digest is invalid");
    }
    if (digest(readRegularFile(resolve(root, name))) !== expected) {
      throw new Error("Pi artifact digest mismatch");
    }
  }
  const unsigned = {
    files: receipt.files,
    host: receipt.host,
    host_version: receipt.host_version,
    package: receipt.package,
    package_version: receipt.package_version,
    schema: receipt.schema,
  };
  const calculated = digest(canonicalJson(unsigned));
  if (
    calculated !== receipt.artifact_authority_id ||
    calculated !== expectedAuthorityId
  ) {
    throw new Error("Pi artifact authority binding is invalid");
  }
  return receipt;
}
