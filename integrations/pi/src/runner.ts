import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const MAX_OUTPUT_BYTES = 1_048_576;
const DEFAULT_TIMEOUT_MS = 120_000;
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
  "ECHO_VEIL_CAPACITY",
  "ECHO_VEIL_EMBEDDER",
  "ECHO_VEIL_EMBEDDING_DIMENSION",
  "ECHO_VEIL_EMBEDDING_MODEL",
  "ECHO_VEIL_EMBEDDING_TIMEOUT",
  "ECHO_VEIL_OLLAMA_URL",
  "ECHO_VEIL_PROFILE",
  "ECHO_VEIL_PROFILE_LOCK_TIMEOUT",
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
  env.ECHO_VEIL_PROFILE = env.ECHO_VEIL_PROFILE || "pi-qwen3";
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

export async function runEchoVeilRpc(
  action: string,
  argumentsValue: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<unknown> {
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
