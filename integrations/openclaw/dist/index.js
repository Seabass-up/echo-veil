import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Type } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
const configSchema = Type.Object({
    projectPath: Type.Optional(Type.String()),
    executable: Type.Optional(Type.String()),
    stateDir: Type.Optional(Type.String()),
    profile: Type.Optional(Type.String({ pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" })),
    timeoutMs: Type.Optional(Type.Integer({ minimum: 1_000, maximum: 120_000 })),
}, { additionalProperties: false });
const MAX_OUTPUT_BYTES = 1_048_576;
export function buildInvocation(config) {
    const env = { ...process.env };
    if (config.stateDir?.trim())
        env.ECHO_VEIL_STATE_DIR = config.stateDir.trim();
    env.ECHO_VEIL_PROFILE = config.profile?.trim() || env.ECHO_VEIL_PROFILE || "openclaw";
    const executable = config.executable?.trim() || process.env.ECHO_VEIL_AGENT_COMMAND?.trim();
    if (executable) {
        return {
            command: executable,
            args: ["rpc"],
            env,
            timeoutMs: config.timeoutMs ?? 30_000,
        };
    }
    const configuredProject = config.projectPath?.trim() || process.env.ECHO_VEIL_PROJECT_ROOT?.trim();
    const developmentRoot = fileURLToPath(new URL("../../../", import.meta.url));
    const projectPath = configuredProject ||
        (existsSync(`${developmentRoot}/pyproject.toml`) ? developmentRoot : undefined);
    if (projectPath) {
        return {
            command: "uv",
            args: [
                "run",
                "--project",
                projectPath,
                "--locked",
                "echo-veil-agent",
                "rpc",
            ],
            env,
            timeoutMs: config.timeoutMs ?? 30_000,
        };
    }
    return {
        command: "echo-veil-agent",
        args: ["rpc"],
        env,
        timeoutMs: config.timeoutMs ?? 30_000,
    };
}
export async function runEchoVeilRpc(action, argumentsValue, config, signal) {
    const invocation = buildInvocation(config);
    return new Promise((resolve, reject) => {
        const child = spawn(invocation.command, invocation.args, {
            env: invocation.env,
            shell: false,
            stdio: ["pipe", "pipe", "pipe"],
        });
        const stdout = [];
        const stderr = [];
        let outputBytes = 0;
        let stderrBytes = 0;
        let settled = false;
        const finish = (callback) => {
            if (settled)
                return;
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
        }, invocation.timeoutMs);
        if (signal?.aborted) {
            abort();
            return;
        }
        signal?.addEventListener("abort", abort, { once: true });
        child.on("error", (error) => finish(() => reject(error)));
        child.stdin.on("error", (error) => finish(() => reject(error)));
        child.stdout.on("data", (chunk) => {
            outputBytes += chunk.length;
            if (outputBytes > MAX_OUTPUT_BYTES) {
                child.kill("SIGTERM");
                finish(() => reject(new Error("Echo Veil response exceeded size limit")));
                return;
            }
            stdout.push(chunk);
        });
        child.stderr.on("data", (chunk) => {
            const remaining = 16_384 - stderrBytes;
            if (remaining <= 0)
                return;
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
                }
                catch {
                    reject(new Error("Echo Veil returned invalid JSON"));
                }
            });
        });
        child.stdin.end(JSON.stringify({ action, arguments: argumentsValue }));
    });
}
export default defineToolPlugin({
    id: "echo-veil",
    name: "Echo Veil",
    description: "Local encrypted, decay-driven memory tools backed by Echo Veil.",
    configSchema,
    tools: (tool) => [
        tool({
            name: "echo_veil_remember",
            label: "Echo Veil Remember",
            description: "Store one user-authorized durable memory locally. Exact retries are deduplicated.",
            optional: true,
            parameters: Type.Object({
                topic: Type.String({ minLength: 1, maxLength: 512 }),
                payload: Type.String({ minLength: 1, maxLength: 100_000 }),
            }),
            execute: async ({ topic, payload }, config, context) => runEchoVeilRpc("remember", { topic, payload }, config, context.signal),
        }),
        tool({
            name: "echo_veil_recall",
            label: "Echo Veil Recall",
            description: "Recall relevant local memories, advance decay, and withhold confidence-gated payloads.",
            parameters: Type.Object({
                query: Type.String({ minLength: 1, maxLength: 20_000 }),
                topK: Type.Optional(Type.Integer({ minimum: 1, maximum: 20 })),
                minScore: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
                allowInferential: Type.Optional(Type.Boolean({
                    description: "Set only after explicit user authorization for inferential recall.",
                })),
            }),
            execute: async ({ query, topK = 5, minScore = 0.35, allowInferential = false }, config, context) => runEchoVeilRpc("recall", {
                query,
                top_k: topK,
                min_score: minScore,
                allow_inferential: allowInferential,
            }, config, context.signal),
        }),
        tool({
            name: "echo_veil_forget",
            label: "Echo Veil Forget",
            description: "Delete one local payload and its matching lifecycle/index state.",
            optional: true,
            parameters: Type.Object({
                vineId: Type.String({ minLength: 1, maxLength: 128 }),
            }),
            execute: async ({ vineId }, config, context) => runEchoVeilRpc("forget", { vine_id: vineId }, config, context.signal),
        }),
        tool({
            name: "echo_veil_doctor",
            label: "Echo Veil Doctor",
            description: "Report local adapter health and explicit production limitations.",
            parameters: Type.Object({}),
            execute: async (_arguments, config, context) => runEchoVeilRpc("doctor", {}, config, context.signal),
        }),
    ],
});
