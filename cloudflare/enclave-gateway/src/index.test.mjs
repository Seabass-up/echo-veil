import assert from "node:assert/strict";
import test from "node:test";

import {
  BodyLimitError,
  readBoundedBody,
  validatedOrigin,
  validatedTeamDomain,
} from "./index.ts";

function stream(...chunks) {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(new Uint8Array(chunk));
      controller.close();
    },
  });
}

test("bounded reader accepts a body at the limit", async () => {
  const result = await readBoundedBody(stream([1, 2], [3, 4]), 4);
  assert.deepEqual([...new Uint8Array(result)], [1, 2, 3, 4]);
});

test("bounded reader rejects a streamed body before buffering past the limit", async () => {
  await assert.rejects(
    readBoundedBody(stream([1, 2, 3], [4, 5]), 4),
    BodyLimitError,
  );
});

test("deployment URLs fail closed", () => {
  assert.equal(validatedOrigin("http://origin.example.com"), null);
  assert.equal(validatedOrigin("https://user:pass@origin.example.com"), null);
  assert.equal(validatedTeamDomain("https://example.com"), null);
  assert.equal(
    validatedTeamDomain("https://team.cloudflareaccess.com")?.origin,
    "https://team.cloudflareaccess.com",
  );
});
