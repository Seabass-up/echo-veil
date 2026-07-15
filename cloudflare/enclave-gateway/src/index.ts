import { createRemoteJWKSet, jwtVerify } from "jose";

interface Env {
  TEAM_DOMAIN: string;
  POLICY_AUD: string;
  ENCLAVE_ORIGIN: string;
  ENCLAVE_ORIGIN_TOKEN: string;
  ENCLAVE_MTLS: Fetcher;
}

const ALLOWED_PATHS = new Set([
  "/v1/attest",
  "/v1/challenge",
  "/v1/session",
  "/v1/vector/encrypt",
  "/v1/vector/similarity",
]);
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const jwksByIssuer = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function jsonError(status: number, message: string): Response {
  return Response.json(
    { error: message },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}

async function authenticate(request: Request, env: Env): Promise<void> {
  const assertion = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!assertion) throw new Error("missing Cloudflare Access assertion");
  const issuer = env.TEAM_DOMAIN.replace(/\/$/, "");
  let jwks = jwksByIssuer.get(issuer);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
    jwksByIssuer.set(issuer, jwks);
  }
  await jwtVerify(assertion, jwks, {
    issuer,
    audience: env.POLICY_AUD,
    algorithms: ["RS256"],
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      try {
        await authenticate(request, env);
      } catch {
        return jsonError(403, "Cloudflare Access validation failed");
      }
      const origin = validatedOrigin(env.ENCLAVE_ORIGIN);
      if (!origin) return jsonError(500, "invalid enclave origin");
      try {
        const upstream = await env.ENCLAVE_MTLS.fetch(
          new URL("/healthz", origin).toString(),
          {
            method: "GET",
            headers: {
              "Authorization": `Bearer ${env.ENCLAVE_ORIGIN_TOKEN}`,
              "Accept": "application/json",
              "Cache-Control": "no-store",
            },
          },
        );
        if (!upstream.ok) return jsonError(502, "enclave health check failed");
        const response = await upstream.arrayBuffer();
        if (response.byteLength > 64 * 1024) {
          return jsonError(502, "enclave health response too large");
        }
        return new Response(response, {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
          },
        });
      } catch {
        return jsonError(502, "enclave origin unavailable");
      }
    }
    if (request.method !== "POST") return jsonError(405, "POST required");
    if (!ALLOWED_PATHS.has(url.pathname)) return jsonError(404, "not found");
    const requestType = request.headers.get("Content-Type") ?? "";
    if (!requestType.toLowerCase().startsWith("application/json")) {
      return jsonError(415, "application/json required");
    }

    try {
      await authenticate(request, env);
    } catch {
      return jsonError(403, "Cloudflare Access validation failed");
    }

    const contentLength = Number(request.headers.get("Content-Length") ?? "0");
    if (!Number.isFinite(contentLength) || contentLength > MAX_REQUEST_BYTES) {
      return jsonError(413, "request too large");
    }
    const body = await request.arrayBuffer();
    if (body.byteLength === 0 || body.byteLength > MAX_REQUEST_BYTES) {
      return jsonError(413, "invalid request size");
    }

    const origin = validatedOrigin(env.ENCLAVE_ORIGIN);
    if (!origin) return jsonError(500, "invalid enclave origin");
    const target = new URL(url.pathname, origin);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    let upstream: Response;
    try {
      upstream = await env.ENCLAVE_MTLS.fetch(target.toString(), {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.ENCLAVE_ORIGIN_TOKEN}`,
          "Content-Type": "application/json",
          "Accept": "application/json",
          "Cache-Control": "no-store",
        },
        body,
        signal: controller.signal,
      });
    } catch {
      return jsonError(502, "enclave origin unavailable");
    } finally {
      clearTimeout(timeout);
    }

    const responseBody = await upstream.arrayBuffer();
    if (responseBody.byteLength > MAX_RESPONSE_BYTES) {
      return jsonError(502, "enclave response too large");
    }
    if (!upstream.ok) return jsonError(502, "enclave origin rejected request");
    const contentType = upstream.headers.get("Content-Type") ?? "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return jsonError(502, "enclave origin returned invalid content type");
    }
    return new Response(responseBody, {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
} satisfies ExportedHandler<Env>;

function validatedOrigin(value: string): URL | null {
  try {
    const origin = new URL(value);
    if (
      origin.protocol !== "https:" ||
      origin.username ||
      origin.password ||
      origin.search ||
      origin.hash ||
      (origin.pathname !== "/" && origin.pathname !== "")
    ) {
      return null;
    }
    return origin;
  } catch {
    return null;
  }
}
