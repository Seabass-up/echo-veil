import assert from "node:assert/strict";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { writeGeneratedConfig } from "./render-config.mjs";

test("generated config atomically replaces a symlink without following it", () => {
  const directory = mkdtempSync(join(tmpdir(), "echo-veil-wrangler-"));
  try {
    const target = join(directory, "must-not-change.json");
    const output = join(directory, "generated.json");
    writeFileSync(target, "sentinel\n", { mode: 0o600 });
    symlinkSync(target, output);

    writeGeneratedConfig({ safe: "value" }, output);

    assert.equal(readFileSync(target, "utf8"), "sentinel\n");
    assert.equal(lstatSync(output).isSymbolicLink(), false);
    assert.equal(readFileSync(output, "utf8"), '{\n  "safe": "value"\n}\n');
    assert.equal(statSync(output).mode & 0o777, 0o600);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});
