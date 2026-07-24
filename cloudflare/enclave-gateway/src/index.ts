import { createRemoteJWKSet, jwtVerify } from "jose";

type Env = CloudflareBindings & {
  ENCLAVE_ORIGIN_TOKEN: string;
};

const ALLOWED_PATHS = new Set([
  "/v1/attest",
  "/v1/challenge",
  "/v1/session",
  "/v1/vector/encrypt",
  "/v1/vector/similarity",
]);
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const MAX_HEALTH_RESPONSE_BYTES = 64 * 1024;
const MAX_ACCESS_ASSERTION_BYTES = 16 * 1024;
const MAX_CONFIG_VALUE_BYTES = 4096;
const ORIGIN_TIMEOUT_MS = 10_000;
const jwksByIssuer = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export class BodyLimitError extends Error {}

function validConfigValue(value: unknown, maximum = MAX_CONFIG_VALUE_BYTES): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    new TextEncoder().encode(value).byteLength <= maximum &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

export function validOriginToken(value: unknown): value is string {
  if (!validConfigValue(value)) return false;
  const encoded = new TextEncoder().encode(value);
  return (
    encoded.byteLength >= 32 &&
    [...value].every((character) => {
      const code = character.codePointAt(0) ?? 0;
      return code >= 33 && code <= 126;
    })
  );
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

export function isJsonContentType(value: string | null): boolean {
  return value?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

function decodeJsonObject(body: ArrayBuffer): Record<string, unknown> | null {
  try {
    const decoded: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(body),
    );
    if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
      return null;
    }
    return decoded as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function validOriginJson(path: string, body: ArrayBuffer): boolean {
  const decoded = decodeJsonObject(body);
  if (!decoded) return false;
  if (path === "/healthz") {
    return (
      hasExactKeys(decoded, ["ckks", "key_id", "platform", "provider_id", "ready", "zkp"]) &&
      decoded.ready === true &&
      decoded.ckks === true &&
      decoded.zkp === true &&
      typeof decoded.key_id === "string" &&
      decoded.key_id.length > 0 &&
      typeof decoded.platform === "string" &&
      decoded.platform.length > 0 &&
      typeof decoded.provider_id === "string" &&
      decoded.provider_id.length > 0
    );
  }
  if (path === "/v1/attest") {
    return (
      hasExactKeys(decoded, ["evidence_b64"]) &&
      typeof decoded.evidence_b64 === "string" &&
      decoded.evidence_b64.length > 0
    );
  }
  return (
    hasExactKeys(decoded, ["ciphertext_b64", "nonce_b64"]) &&
    typeof decoded.nonce_b64 === "string" &&
    decoded.nonce_b64.length > 0 &&
    typeof decoded.ciphertext_b64 === "string" &&
    decoded.ciphertext_b64.length > 0
  );
}

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

function responseHeaders(
  requestId: string,
  additional: Record<string, string> = {},
): Headers {
  return new Headers({
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Request-ID": requestId,
    ...additional,
  });
}

function jsonError(
  status: number,
  message: string,
  requestId: string,
  additional: Record<string, string> = {},
): Response {
  return Response.json(
    { error: message },
    {
      status,
      headers: responseHeaders(requestId, additional),
    },
  );
}

function logFailure(requestId: string, path: string, reason: string): void {
  console.error(
    JSON.stringify({
      event: "echo_veil_gateway_failure",
      path,
      reason,
      request_id: requestId,
    }),
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
  if (!validConfigValue(env.POLICY_AUD)) {
    throw new Error("invalid Cloudflare Access audience");
  }
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
    const requestId = crypto.randomUUID();
    if (url.search) return jsonError(404, "not found", requestId);
    if (request.method === "GET" && url.pathname === "/healthz") {
      try {
        await authenticate(request, env);
      } catch {
        logFailure(requestId, url.pathname, "access_denied");
        return jsonError(403, "Cloudflare Access validation failed", requestId);
      }
      const origin = validatedOrigin(env.ENCLAVE_ORIGIN);
      if (!origin || !validOriginToken(env.ENCLAVE_ORIGIN_TOKEN)) {
        logFailure(requestId, url.pathname, "invalid_origin_configuration");
        return jsonError(500, "invalid enclave origin configuration", requestId);
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), ORIGIN_TIMEOUT_MS);
      try {
        const upstream = await env.ENCLAVE_MTLS.fetch(
          new URL("/healthz", origin).toString(),
          {
            method: "GET",
            redirect: "manual",
            headers: {
              "Authorization": `Bearer ${env.ENCLAVE_ORIGIN_TOKEN}`,
              "Accept": "application/json",
              "Cache-Control": "no-store",
              "X-Request-ID": requestId,
            },
            signal: controller.signal,
          },
        );
        if (!upstream.ok) {
          await upstream.body?.cancel();
          logFailure(requestId, url.pathname, "origin_health_rejected");
          return jsonError(502, "enclave health check failed", requestId, {
            "Retry-After": "1",
          });
        }
        if (!isJsonContentType(upstream.headers.get("Content-Type"))) {
          await upstream.body?.cancel();
          throw new Error("invalid health content type");
        }
        validateDeclaredLength(upstream.headers, MAX_HEALTH_RESPONSE_BYTES);
        const response = await readBoundedBody(
          upstream.body,
          MAX_HEALTH_RESPONSE_BYTES,
        );
        if (!validOriginJson("/healthz", response)) {
          throw new Error("invalid health response");
        }
        return new Response(response, {
          status: 200,
          headers: responseHeaders(requestId, {
            "Content-Length": String(response.byteLength),
            "Content-Type": "application/json",
          }),
        });
      } catch {
        logFailure(requestId, url.pathname, "origin_health_unavailable");
        return jsonError(502, "enclave origin unavailable", requestId, {
          "Retry-After": "1",
        });
      } finally {
        clearTimeout(timeout);
      }
    }
    if (request.method !== "POST") {
      return jsonError(405, "POST required", requestId, { Allow: "POST" });
    }
    if (!ALLOWED_PATHS.has(url.pathname)) {
      return jsonError(404, "not found", requestId);
    }
    const requestType = request.headers.get("Content-Type") ?? "";
    if (!isJsonContentType(requestType)) {
      return jsonError(415, "application/json required", requestId);
    }

    try {
      await authenticate(request, env);
    } catch {
      logFailure(requestId, url.pathname, "access_denied");
      return jsonError(403, "Cloudflare Access validation failed", requestId);
    }

    let body: ArrayBuffer;
    try {
      validateDeclaredLength(request.headers, MAX_REQUEST_BYTES);
      body = await readBoundedBody(request.body, MAX_REQUEST_BYTES);
    } catch {
      return jsonError(413, "request too large", requestId);
    }
    if (body.byteLength === 0 || body.byteLength > MAX_REQUEST_BYTES) {
      return jsonError(413, "invalid request size", requestId);
    }

    const origin = validatedOrigin(env.ENCLAVE_ORIGIN);
    if (!origin || !validOriginToken(env.ENCLAVE_ORIGIN_TOKEN)) {
      logFailure(requestId, url.pathname, "invalid_origin_configuration");
      return jsonError(500, "invalid enclave origin configuration", requestId);
    }
    const target = new URL(url.pathname, origin);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), ORIGIN_TIMEOUT_MS);
    let upstream: Response;
    try {
      upstream = await env.ENCLAVE_MTLS.fetch(target.toString(), {
        method: "POST",
        redirect: "manual",
        headers: {
          "Authorization": `Bearer ${env.ENCLAVE_ORIGIN_TOKEN}`,
          "Content-Type": "application/json",
          "Accept": "application/json",
          "Cache-Control": "no-store",
          "X-Request-ID": requestId,
        },
        body,
        signal: controller.signal,
      });
    } catch {
      clearTimeout(timeout);
      logFailure(requestId, url.pathname, "origin_unavailable");
      return jsonError(502, "enclave origin unavailable", requestId, {
        "Retry-After": "1",
      });
    }

    if (!upstream.ok) {
      await upstream.body?.cancel();
      clearTimeout(timeout);
      logFailure(requestId, url.pathname, "origin_rejected");
      return jsonError(502, "enclave origin rejected request", requestId);
    }
    if (!isJsonContentType(upstream.headers.get("Content-Type"))) {
      await upstream.body?.cancel();
      clearTimeout(timeout);
      logFailure(requestId, url.pathname, "invalid_origin_content_type");
      return jsonError(502, "enclave origin returned invalid content type", requestId);
    }

    let responseBody: ArrayBuffer;
    try {
      validateDeclaredLength(upstream.headers, MAX_RESPONSE_BYTES);
      responseBody = await readBoundedBody(upstream.body, MAX_RESPONSE_BYTES);
    } catch (error) {
      const reason =
        error instanceof BodyLimitError ? "origin_response_too_large" : "origin_unavailable";
      logFailure(requestId, url.pathname, reason);
      return jsonError(502, "enclave response unavailable", requestId, {
        "Retry-After": "1",
      });
    } finally {
      clearTimeout(timeout);
    }
    if (!validOriginJson(url.pathname, responseBody)) {
      logFailure(requestId, url.pathname, "invalid_origin_response");
      return jsonError(502, "enclave origin returned an invalid response", requestId);
    }
    return new Response(responseBody, {
      status: 200,
      headers: responseHeaders(requestId, {
        "Content-Length": String(responseBody.byteLength),
        "Content-Type": "application/json",
      }),
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
  if (
    !teamDomain ||
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/i.test(
      teamDomain.hostname,
    )
  ) {
    return null;
  }
  return teamDomain;
}
