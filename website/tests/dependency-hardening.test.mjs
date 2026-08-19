import assert from "node:assert/strict";
import test from "node:test";

import { imageSize, imageSizeFromFile, types } from "image-size";

test("the vulnerable local image parser is replaced by a fail-closed adapter", async () => {
  assert.deepEqual(types, []);
  assert.throws(
    () => imageSize(new Uint8Array([0x69, 0x63, 0x6e, 0x73])),
    /Local image dimension parsing is disabled/,
  );
  await assert.rejects(
    imageSizeFromFile("untrusted.icns"),
    /Local image dimension parsing is disabled/,
  );
});
