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
    ]);
  });

  it("uses an isolated Pi profile and a shell-free invocation", () => {
    const previous = process.env.ECHO_VEIL_PROFILE;
    delete process.env.ECHO_VEIL_PROFILE;
    try {
      const invocation = buildInvocation();
      expect(invocation.env.ECHO_VEIL_PROFILE).toBe("pi");
      expect(invocation.command).not.toMatch(/[;&|]/);
      expect(invocation.args.at(-1)).toBe("rpc");
    } finally {
      if (previous === undefined) delete process.env.ECHO_VEIL_PROFILE;
      else process.env.ECHO_VEIL_PROFILE = previous;
    }
  });
});
