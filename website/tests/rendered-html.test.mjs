import assert from "node:assert/strict";
import { access, readFile, stat } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the complete Echo Veil product page", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Echo Veil — A Wiser Memory for AI Agents<\/title>/i);
  assert.match(html, /Memory that knows/);
  assert.match(html, /what to keep\./);
  assert.match(html, /A memory garden/);
  assert.match(html, /Customer &amp; field copilots/);
  assert.match(html, /The policy layer between/);
  assert.match(html, /Attested enclave \+ ZKP gate/);
  assert.match(html, /https:\/\/echo\.algo-cli\.com\/og\.png/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape/);
});

test("ships production metadata, social art, and no starter skeleton", async () => {
  const [page, layout, packageJson, socialImage] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    stat(new URL("../public/og.png", import.meta.url)),
  ]);

  assert.match(page, /id="system"/);
  assert.match(page, /id="use-cases"/);
  assert.match(page, /id="stack"/);
  assert.match(layout, /metadataBase: new URL\("https:\/\/echo\.algo-cli\.com"\)/);
  assert.match(layout, /images: \["\/og\.png"\]/);
  assert.doesNotMatch(page, /SkeletonPreview|codex-preview/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  assert.ok(socialImage.size > 100_000);

  await assert.rejects(
    access(new URL("../app/_sites-preview/SkeletonPreview.tsx", import.meta.url)),
  );
});
