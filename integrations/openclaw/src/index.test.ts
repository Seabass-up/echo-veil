import { describe, expect, it } from "vitest";
import { getToolPluginMetadata } from "openclaw/plugin-sdk/tool-plugin";

import entry, { buildInvocation } from "./index.js";

describe("echo-veil OpenClaw plugin", () => {
  it("declares the native tool contract", () => {
    expect(getToolPluginMetadata(entry)?.tools.map((tool) => tool.name)).toEqual([
      "echo_veil_remember",
      "echo_veil_recall",
      "echo_veil_forget",
      "echo_veil_doctor",
      "echo_veil_reindex",
    ]);
  });

  it("uses an explicit executable without a shell", () => {
    const invocation = buildInvocation({
      executable: "/opt/tools/echo-veil-agent",
      stateDir: "/private/state",
      profile: "shared",
      timeoutMs: 12_000,
    });

    expect(invocation.command).toBe("/opt/tools/echo-veil-agent");
    expect(invocation.args).toEqual(["rpc"]);
    expect(invocation.env.ECHO_VEIL_STATE_DIR).toBe("/private/state");
    expect(invocation.env.ECHO_VEIL_PROFILE).toBe("shared");
    expect(invocation.env.ECHO_VEIL_EMBEDDER).toBe("ollama");
    expect(invocation.env.ECHO_VEIL_EMBEDDING_MODEL).toBe("qwen3-embedding:latest");
    expect(invocation.env.ECHO_VEIL_EMBEDDING_DIMENSION).toBe("1024");
    expect(invocation.timeoutMs).toBe(12_000);
  });

  it("runs a configured source checkout through uv", () => {
    const invocation = buildInvocation({ projectPath: "/src/echo-veil" });

    expect(invocation.command).toBe("uv");
    expect(invocation.args).toEqual([
      "run",
      "--project",
      "/src/echo-veil",
      "--locked",
      "echo-veil-agent",
      "rpc",
    ]);
    expect(invocation.env.ECHO_VEIL_PROFILE).toBe("openclaw-qwen3");
  });
});
