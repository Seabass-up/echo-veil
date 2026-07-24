import assert from "node:assert/strict";
import test from "node:test";

import {
  BodyLimitError,
  default as gateway,
  isJsonContentType,
  readBoundedBody,
  validatedOrigin,
  validatedTeamDomain,
  validOriginToken,
  validOriginJson,
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
  assert.equal(validatedTeamDomain("https://nested.team.cloudflareaccess.com"), null);
  assert.equal(
    validatedTeamDomain("https://team.cloudflareaccess.com")?.origin,
    "https://team.cloudflareaccess.com",
  );
});

test("origin tokens are bounded printable secrets", () => {
  assert.equal(validOriginToken("a".repeat(32)), true);
  assert.equal(validOriginToken("short"), false);
  assert.equal(validOriginToken(`a${"b".repeat(31)}\n`), false);
  assert.equal(validOriginToken(`a${"b".repeat(31)}é`), false);
});

test("content type matching rejects JSON lookalikes", () => {
  assert.equal(isJsonContentType("application/json; charset=utf-8"), true);
  assert.equal(isJsonContentType("application/json-malicious"), false);
  assert.equal(isJsonContentType("text/plain"), false);
  assert.equal(isJsonContentType(null), false);
});

test("origin response validation enforces endpoint shape", () => {
  const encode = (value) => new TextEncoder().encode(JSON.stringify(value)).buffer;

  assert.equal(
    validOriginJson(
      "/healthz",
      encode({
        ready: true,
        provider_id: "provider",
        key_id: "key",
        platform: "sev-snp",
        ckks: true,
        zkp: true,
      }),
    ),
    true,
  );
  assert.equal(validOriginJson("/healthz", encode({ ready: "yes" })), false);
  assert.equal(
    validOriginJson("/v1/attest", encode({ evidence_b64: "evidence" })),
    true,
  );
  assert.equal(
    validOriginJson(
      "/v1/attest",
      encode({ evidence_b64: "evidence", unexpected: "field" }),
    ),
    false,
  );
  assert.equal(
    validOriginJson(
      "/v1/challenge",
      encode({ nonce_b64: "nonce", ciphertext_b64: "ciphertext" }),
    ),
    true,
  );
  assert.equal(validOriginJson("/v1/session", encode({ session: "leak" })), false);
  assert.equal(validOriginJson("/v1/session", new Uint8Array([0xff]).buffer), false);
});

test("gateway errors carry safe correlation and cache headers", async () => {
  const response = await gateway.fetch(
    new Request("https://memory.algo-cli.com/v1/session?unexpected=true", {
      method: "POST",
    }),
    {},
  );

  assert.equal(response.status, 404);
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
  assert.match(response.headers.get("X-Request-ID") ?? "", /^[0-9a-f-]{36}$/i);
  assert.deepEqual(await response.json(), { error: "not found" });
});
