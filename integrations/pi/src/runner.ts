import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, lstatSync } from "node:fs";
import { createConnection } from "node:net";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_OUTPUT_BYTES = 1_048_576;
const DEFAULT_TIMEOUT_MS = 120_000;
const BROKER_SCHEMA = "echo-veil-local-broker-v1";
const BROKER_TELEMETRY_SCHEMA = "echo-veil-broker-latency-v1";
const CHILD_ENV_ALLOWLIST = new Set([
  "HOME",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "TMPDIR",
  "HOMEDRIVE",
  "HOMEPATH",
  "USERPROFILE",
  "UV_CACHE_DIR",
  "UV_PYTHON",
  "UV_PYTHON_INSTALL_DIR",
  "VIRTUAL_ENV",
  "WINDIR",
]);
const CHILD_ECHO_ENV_ALLOWLIST = new Set([
  "ECHO_VEIL_AVAILABILITY_LAYER",
  "ECHO_VEIL_BROKER_SOCKET",
  "ECHO_VEIL_CAPACITY",
  "ECHO_VEIL_CALLER",
  "ECHO_VEIL_EMBEDDER",
  "ECHO_VEIL_EMBEDDING_DIMENSION",
  "ECHO_VEIL_EMBEDDING_MODEL",
  "ECHO_VEIL_EMBEDDING_TIMEOUT",
  "ECHO_VEIL_OLLAMA_URL",
  "ECHO_VEIL_PROFILE",
  "ECHO_VEIL_PROFILE_LOCK_TIMEOUT",
  "ECHO_VEIL_SCOPE",
  "ECHO_VEIL_STATE_DIR",
]);

export type EchoVeilInvocation = {
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv;
};

export function buildChildEnvironment(
  source: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(source).filter(
      ([name, value]) =>
        value !== undefined &&
        (CHILD_ENV_ALLOWLIST.has(name) || CHILD_ECHO_ENV_ALLOWLIST.has(name)),
    ),
  );
}

export function buildInvocation(): EchoVeilInvocation {
  const env = buildChildEnvironment();
  env.ECHO_VEIL_PROFILE = env.ECHO_VEIL_PROFILE || "echo-universal-qwen3-v1";
  env.ECHO_VEIL_SCOPE = env.ECHO_VEIL_SCOPE || "local-user";
  env.ECHO_VEIL_CALLER = "pi";
  env.ECHO_VEIL_EMBEDDER = env.ECHO_VEIL_EMBEDDER || "ollama";
  env.ECHO_VEIL_EMBEDDING_MODEL = env.ECHO_VEIL_EMBEDDING_MODEL || "qwen3-embedding:latest";
  env.ECHO_VEIL_EMBEDDING_DIMENSION = env.ECHO_VEIL_EMBEDDING_DIMENSION || "1024";
  env.ECHO_VEIL_AVAILABILITY_LAYER = env.ECHO_VEIL_AVAILABILITY_LAYER || "true";
  const executable = process.env.ECHO_VEIL_AGENT_COMMAND?.trim();
  if (executable) return { command: executable, args: ["rpc"], env };

  const configuredProject = process.env.ECHO_VEIL_PROJECT_ROOT?.trim();
  const developmentRoot = fileURLToPath(new URL("../../../", import.meta.url));
  const projectPath = configuredProject ||
    (existsSync(`${developmentRoot}/pyproject.toml`) ? developmentRoot : undefined);
  if (projectPath) {
    return {
      command: "uv",
      args: ["run", "--project", projectPath, "--locked", "echo-veil-agent", "rpc"],
      env,
    };
  }
  return { command: "echo-veil-agent", args: ["rpc"], env };
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new Error(`${label} is invalid`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length &&
    actual.every((name, index) => name === wanted[index]);
}

function brokerSocketPath(): string | undefined {
  const value = process.env.ECHO_VEIL_BROKER_SOCKET?.trim();
  if (!value) return undefined;
  if (process.platform === "win32" || !isAbsolute(value)) {
    throw new Error("Echo Veil broker socket is invalid");
  }
  const information = lstatSync(value);
  if (
    !information.isSocket() ||
    (information.mode & 0o077) !== 0 ||
    (typeof process.getuid === "function" && information.uid !== process.getuid())
  ) {
    throw new Error("Echo Veil broker socket is not owner-only");
  }
  return value;
}

async function runBrokerRpc(
  socketPath: string,
  action: string,
  argumentsValue: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<unknown> {
  const requestId = randomBytes(16).toString("hex");
  const request = `${JSON.stringify({
    action,
    arguments: argumentsValue,
    caller: "pi",
    request_id: requestId,
    schema: BROKER_SCHEMA,
  })}\n`;
  if (Buffer.byteLength(request) > MAX_OUTPUT_BYTES) {
    throw new Error("Echo Veil broker request exceeded size limit");
  }
  const started = performance.now();
  return new Promise((resolve, reject) => {
    const connection = createConnection({ path: socketPath });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      connection.destroy();
      callback();
    };
    const abort = () => finish(() => reject(
      new Error("Echo Veil broker request aborted"),
    ));
    const timeout = setTimeout(() => finish(() => reject(
      new Error("Echo Veil broker request timed out"),
    )), DEFAULT_TIMEOUT_MS);
    if (signal?.aborted) {
      abort();
      return;
    }
    signal?.addEventListener("abort", abort, { once: true });
    connection.on("connect", () => connection.end(request));
    connection.on("error", () => finish(() => reject(
      new Error("Echo Veil broker is unavailable"),
    )));
    connection.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES) {
        finish(() => reject(
          new Error("Echo Veil broker response exceeded size limit"),
        ));
        return;
      }
      chunks.push(chunk);
    });
    connection.on("end", () => finish(() => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        const newline = raw.indexOf("\n");
        if (newline < 1 || raw.slice(newline + 1).trim()) {
          throw new Error("invalid framing");
        }
        const response = objectValue(
          JSON.parse(raw.slice(0, newline)) as unknown,
          "broker response",
        );
        const success = response.ok === true;
        if (
          response.schema !== BROKER_SCHEMA ||
          response.request_id !== requestId ||
          !exactKeys(
            response,
            success
              ? ["ok", "request_id", "result", "schema", "telemetry"]
              : ["error", "ok", "request_id", "schema", "telemetry"],
          )
        ) {
          throw new Error("invalid response binding");
        }
        const telemetry = objectValue(response.telemetry, "broker telemetry");
        if (
          !exactKeys(
            telemetry,
            ["dispatch_ms", "payload_included", "schema"],
          ) ||
          telemetry.schema !== BROKER_TELEMETRY_SCHEMA ||
          telemetry.payload_included !== false ||
          typeof telemetry.dispatch_ms !== "number" ||
          !Number.isFinite(telemetry.dispatch_ms) ||
          telemetry.dispatch_ms < 0 ||
          telemetry.dispatch_ms > DEFAULT_TIMEOUT_MS
        ) {
          throw new Error("invalid broker telemetry");
        }
        if (!success) {
          if (response.error !== "request_failed") {
            throw new Error("invalid broker error");
          }
          throw new Error("Echo Veil broker request failed");
        }
        const result = objectValue(response.result, "broker result");
        resolve({
          ...result,
          broker_transport: {
            dispatch_ms: telemetry.dispatch_ms,
            payload_included: false,
            round_trip_ms: Math.round((performance.now() - started) * 1_000) /
              1_000,
            schema: BROKER_TELEMETRY_SCHEMA,
          },
        });
      } catch {
        reject(new Error("Echo Veil broker returned invalid data"));
      }
    }));
  });
}

export async function runEchoVeilRpc(
  action: string,
  argumentsValue: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<unknown> {
  const socketPath = brokerSocketPath();
  if (socketPath) {
    return runBrokerRpc(socketPath, action, argumentsValue, signal);
  }
  const invocation = buildInvocation();
  return new Promise((resolve, reject) => {
    const child = spawn(invocation.command, invocation.args, {
      env: invocation.env,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let settled = false;

    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      callback();
    };
    const terminate = () => {
      if (child.exitCode !== null) return;
      child.kill("SIGTERM");
      const escalation = setTimeout(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
      }, 1_000);
      escalation.unref();
      child.once("close", () => clearTimeout(escalation));
    };
    const abort = () => {
      terminate();
      finish(() => reject(new Error("Echo Veil request aborted")));
    };
    const timeout = setTimeout(() => {
      terminate();
      finish(() => reject(new Error("Echo Veil request timed out")));
    }, DEFAULT_TIMEOUT_MS);

    if (signal?.aborted) {
      abort();
      return;
    }
    signal?.addEventListener("abort", abort, { once: true });
    child.on("error", () => finish(() => reject(
      new Error("Echo Veil process could not be started"),
    )));
    child.stdin.on("error", () => finish(() => reject(
      new Error("Echo Veil request could not be delivered"),
    )));
    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        terminate();
        finish(() => reject(new Error("Echo Veil response exceeded size limit")));
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.resume();
    child.on("close", (code) => {
      finish(() => {
        const output = Buffer.concat(stdout).toString("utf8").trim();
        if (code !== 0) {
          reject(new Error(`Echo Veil exited with status ${code ?? "unknown"}`));
          return;
        }
        try {
          const decoded: unknown = JSON.parse(output);
          if (decoded === null || Array.isArray(decoded) || typeof decoded !== "object") {
            throw new TypeError("invalid RPC response");
          }
          resolve(decoded);
        } catch {
          reject(new Error("Echo Veil returned invalid JSON"));
        }
      });
    });
    child.stdin.end(JSON.stringify({ action, arguments: argumentsValue }));
  });
}
