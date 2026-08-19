import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { verifyPiArtifactDirectory } from "../src/artifact.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const receipt = JSON.parse(
  readFileSync(resolve(root, "artifact-receipt.json"), "utf8"),
) as {
  artifact_authority_id: string;
  files: Record<string, string>;
};

function copyArtifact(destination: string): void {
  for (const name of [...Object.keys(receipt.files), "artifact-receipt.json"]) {
    const target = resolve(destination, name);
    mkdirSync(dirname(target), { recursive: true });
    cpSync(resolve(root, name), target);
  }
}

describe("Pi artifact authority", () => {
  it("accepts the exact reviewed artifact and rejects a wrong external pin", () => {
    expect(
      verifyPiArtifactDirectory(root, receipt.artifact_authority_id)
        .artifact_authority_id,
    ).toBe(receipt.artifact_authority_id);
    expect(() => verifyPiArtifactDirectory(
      root,
      `sha256:${"0".repeat(64)}`,
    )).toThrow(/authority binding/);
  });

  it("blocks one-byte artifact drift", () => {
    const destination = mkdtempSync(join(tmpdir(), "echo-veil-pi-artifact-"));
    try {
      copyArtifact(destination);
      const target = resolve(destination, "extensions/index.ts");
      writeFileSync(
        target,
        Buffer.concat([readFileSync(target), Buffer.from("\n")]),
        { mode: 0o600 },
      );

      expect(() => verifyPiArtifactDirectory(
        destination,
        receipt.artifact_authority_id,
      )).toThrow(/digest mismatch/);
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  });
});
