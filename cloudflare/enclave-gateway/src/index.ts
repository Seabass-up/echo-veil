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
const MAX_ACCESS_ASSERTION_BYTES = 16 * 1024;
const ORIGIN_TIMEOUT_MS = 10_000;
const jwksByIssuer = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export class BodyLimitError extends Error {}

function validateDeclaredLength(headers: Headers, maximum: number): void {
  const value = headers.get("Content-Length");
  if (value === null) return;
  if (!/^\d+$/.test(value) || Number(value) > maximum) {
    throw new BodyLimitError("invalid content length");
  }
}

export async function readBoundedBody(
  body: ReadableStream<Uint8Array> | null,
  maximum: number,
): Promise<ArrayBuffer> {
  if (!Number.isSafeInteger(maximum) || maximum < 0) {
    throw new TypeError("maximum body size must be a non-negative safe integer");
  }
  if (body === null) return new ArrayBuffer(0);

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array) || value.byteLength > maximum - total) {
        await reader.cancel();
        throw new BodyLimitError("body exceeds the configured limit");
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output.buffer;
}

function jsonError(status: number, message: string): Response {
  return Response.json(
    { error: message },
    {
      status,
      headers: {
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
      },
    },
  );
}

async function authenticate(request: Request, env: Env): Promise<void> {
  const assertion = request.headers.get("Cf-Access-Jwt-Assertion");
  if (
    !assertion ||
    new TextEncoder().encode(assertion).byteLength > MAX_ACCESS_ASSERTION_BYTES
  ) {
    throw new Error("invalid Cloudflare Access assertion");
  }
  const teamDomain = validatedTeamDomain(env.TEAM_DOMAIN);
  if (!teamDomain) throw new Error("invalid Cloudflare Access team domain");
  const issuer = teamDomain.origin;
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
    if (url.search) return jsonError(404, "not found");
    if (request.method === "GET" && url.pathname === "/healthz") {
      try {
        await authenticate(request, env);
      } catch {
        return jsonError(403, "Cloudflare Access validation failed");
      }
      const origin = validatedOrigin(env.ENCLAVE_ORIGIN);
      if (!origin) return jsonError(500, "invalid enclave origin");
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), ORIGIN_TIMEOUT_MS);
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
            signal: controller.signal,
          },
        );
        if (!upstream.ok) return jsonError(502, "enclave health check failed");
        validateDeclaredLength(upstream.headers, 64 * 1024);
        const response = await readBoundedBody(upstream.body, 64 * 1024);
        return new Response(response, {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
          },
        });
      } catch {
        return jsonError(502, "enclave origin unavailable");
      } finally {
        clearTimeout(timeout);
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

    let body: ArrayBuffer;
    try {
      validateDeclaredLength(request.headers, MAX_REQUEST_BYTES);
      body = await readBoundedBody(request.body, MAX_REQUEST_BYTES);
    } catch {
      return jsonError(413, "request too large");
    }
    if (body.byteLength === 0 || body.byteLength > MAX_REQUEST_BYTES) {
      return jsonError(413, "invalid request size");
    }

    const origin = validatedOrigin(env.ENCLAVE_ORIGIN);
    if (!origin) return jsonError(500, "invalid enclave origin");
    const target = new URL(url.pathname, origin);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), ORIGIN_TIMEOUT_MS);
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
      clearTimeout(timeout);
      return jsonError(502, "enclave origin unavailable");
    }

    let responseBody: ArrayBuffer;
    try {
      validateDeclaredLength(upstream.headers, MAX_RESPONSE_BYTES);
      responseBody = await readBoundedBody(upstream.body, MAX_RESPONSE_BYTES);
    } catch {
      return jsonError(502, "enclave response too large");
    } finally {
      clearTimeout(timeout);
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
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
} satisfies ExportedHandler<Env>;

export function validatedOrigin(value: string): URL | null {
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

export function validatedTeamDomain(value: string): URL | null {
  const teamDomain = validatedOrigin(value);
  if (!teamDomain || !teamDomain.hostname.endsWith(".cloudflareaccess.com")) {
    return null;
  }
  return teamDomain;
}
