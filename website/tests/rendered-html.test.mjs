import assert from "node:assert/strict";
import { access, readFile, stat } from "node:fs/promises";
import test from "node:test";

async function render(method = "GET") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      method,
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
  assert.match(
    response.headers.get("content-security-policy") ?? "",
    /frame-ancestors 'none'/,
  );
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(
    response.headers.get("strict-transport-security") ?? "",
    /max-age=63072000/,
  );

  const html = await response.text();
  assert.match(
    html,
    /<title>Echo Veil v0\.8\.0 — Protected Semantic Memory for AI Agents<\/title>/i,
  );
  assert.match(html, /Memory that knows/);
  assert.match(html, /what to keep\./);
  assert.match(html, /A memory garden/);
  assert.match(html, /Customer &amp; field copilots/);
  assert.match(html, /The policy layer between/);
  assert.match(html, /42 \/ 42 retrieval gate/);
  assert.match(html, /Answerable, not just similar/);
  assert.match(html, /not a universal product comparison/);
  assert.match(html, /ALGO CLI/);
  assert.match(html, /OPENCLAW/);
  assert.match(html, /one versioned local authority/);
  assert.match(html, /CLAUDE CODE/);
  assert.match(html, /MERCURY\*/);
  assert.match(html, /caller identity alone cannot promote memory/i);
  assert.match(html, /Attested enclave/);
  assert.match(html, /Future deployment \+ independent review/);
  assert.match(html, /View source on GitHub/);
  assert.match(html, /href="https:\/\/github\.com\/Seabass-up\/echo-veil">GitHub ↗<\/a>/);
  assert.match(html, /v0\.8\.0 release candidate/);
  assert.match(html, /docs\/AGENT_INTEGRATION\.md/);
  assert.match(html, /Skip to main content/);
  assert.match(html, /rel="canonical" href="https:\/\/echo\.algo-cli\.com\/"/);
  assert.ok(html.includes("https://echo.algo-cli.com/og.png"));
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape/);
});

test("public brochure worker rejects state-changing methods", async () => {
  const response = await render("POST");
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET, HEAD");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.deepEqual(await response.json(), { error: "method not allowed" });
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
