import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const uri = require("fast-uri");

for (const input of [
  "%2f%2fexample.invalid:/memory",
  "%u002f%u002fexample.invalid:/memory",
  "%0d%0aexample:/memory",
]) {
  test(`URI normalization cannot introduce authority or header controls: ${input}`, () => {
    let normalized;
    try {
      normalized = uri.normalize(input);
    } catch (error) {
      // Rejecting a malformed scheme is also a safe result.
      assert.ok(error instanceof Error);
      return;
    }
    assert.equal(uri.parse(normalized).host, undefined);
    assert.doesNotMatch(normalized, /[\r\n]/);
  });
}

test("ordinary URI normalization remains supported", () => {
  const input = "https://example.invalid/memory?layer=short_term#record";
  assert.equal(uri.normalize(input), input);
});
