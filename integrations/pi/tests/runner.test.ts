import { describe, expect, it } from "vitest";

import { echoVeilTools } from "../extensions/index.js";
import { buildInvocation } from "../src/runner.js";

describe("Echo Veil Pi extension", () => {
  it("registers the complete tool contract", () => {
    expect(echoVeilTools.map((tool) => tool.name)).toEqual([
      "echo_veil_remember",
      "echo_veil_recall",
      "echo_veil_forget",
      "echo_veil_doctor",
      "echo_veil_reindex",
    ]);
    const recall = echoVeilTools.find((tool) => tool.name === "echo_veil_recall");
    expect(JSON.stringify(recall?.parameters)).toContain('"minimum":2');
    expect(recall?.description).toContain("not semantic or authoritative recall");
  });

  it("uses an isolated Pi profile and a shell-free invocation", () => {
    const previous = process.env.ECHO_VEIL_PROFILE;
    delete process.env.ECHO_VEIL_PROFILE;
    try {
      const invocation = buildInvocation();
      expect(invocation.env.ECHO_VEIL_PROFILE).toBe("pi-qwen3");
      expect(invocation.env.ECHO_VEIL_EMBEDDER).toBe("ollama");
      expect(invocation.env.ECHO_VEIL_EMBEDDING_MODEL).toBe("qwen3-embedding:latest");
      expect(invocation.env.ECHO_VEIL_EMBEDDING_DIMENSION).toBe("1024");
      expect(invocation.env.ECHO_VEIL_AVAILABILITY_LAYER).toBe("true");
      expect(invocation.command).not.toMatch(/[;&|]/);
      expect(invocation.args.at(-1)).toBe("rpc");
    } finally {
      if (previous === undefined) delete process.env.ECHO_VEIL_PROFILE;
      else process.env.ECHO_VEIL_PROFILE = previous;
    }
  });
});
