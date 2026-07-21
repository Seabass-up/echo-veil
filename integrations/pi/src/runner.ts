import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const MAX_OUTPUT_BYTES = 1_048_576;
const MAX_ERROR_BYTES = 16_384;
const DEFAULT_TIMEOUT_MS = 120_000;

export type EchoVeilInvocation = {
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv;
};

export function buildInvocation(): EchoVeilInvocation {
  const env = { ...process.env };
  env.ECHO_VEIL_PROFILE = env.ECHO_VEIL_PROFILE || "pi-qwen3";
  env.ECHO_VEIL_EMBEDDER = env.ECHO_VEIL_EMBEDDER || "ollama";
  env.ECHO_VEIL_EMBEDDING_MODEL = env.ECHO_VEIL_EMBEDDING_MODEL || "qwen3-embedding:latest";
  env.ECHO_VEIL_EMBEDDING_DIMENSION = env.ECHO_VEIL_EMBEDDING_DIMENSION || "1024";
  env.ECHO_VEIL_AVAILABILITY_LAYER = env.ECHO_VEIL_AVAILABILITY_LAYER || "true";
  const executable = env.ECHO_VEIL_AGENT_COMMAND?.trim();
  if (executable) return { command: executable, args: ["rpc"], env };

  const configuredProject = env.ECHO_VEIL_PROJECT_ROOT?.trim();
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
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;

    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      callback();
    };
    const abort = () => {
      child.kill("SIGTERM");
      finish(() => reject(new Error("Echo Veil request aborted")));
    };
    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
      finish(() => reject(new Error("Echo Veil request timed out")));
    }, DEFAULT_TIMEOUT_MS);

    if (signal?.aborted) {
      abort();
      return;
    }
    signal?.addEventListener("abort", abort, { once: true });
    child.on("error", (error) => finish(() => reject(error)));
    child.stdin.on("error", (error) => finish(() => reject(error)));
    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_OUTPUT_BYTES) {
        child.kill("SIGTERM");
        finish(() => reject(new Error("Echo Veil response exceeded size limit")));
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const remaining = MAX_ERROR_BYTES - stderrBytes;
      if (remaining <= 0) return;
      const bounded = chunk.subarray(0, remaining);
      stderr.push(bounded);
      stderrBytes += bounded.length;
    });
    child.on("close", (code) => {
      finish(() => {
        const output = Buffer.concat(stdout).toString("utf8").trim();
        if (code !== 0) {
          const detail = Buffer.concat(stderr).toString("utf8").trim();
          reject(new Error(detail || `Echo Veil exited with status ${code ?? "unknown"}`));
          return;
        }
        try {
          resolve(JSON.parse(output));
        } catch {
          reject(new Error("Echo Veil returned invalid JSON"));
        }
      });
    });
    child.stdin.end(JSON.stringify({ action, arguments: argumentsValue }));
  });
}
