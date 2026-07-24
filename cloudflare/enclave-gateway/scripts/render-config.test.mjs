import assert from "node:assert/strict";
import {
  closeSync,
  constants,
  fstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
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
    const descriptor = openSync(
      output,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    try {
      assert.equal(
        readFileSync(descriptor, "utf8"),
        '{\n  "safe": "value"\n}\n',
      );
      assert.equal(fstatSync(descriptor).mode & 0o777, 0o600);
    } finally {
      closeSync(descriptor);
    }
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});
