import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { parsePreflightContext } from "./index.js";

type Bundle = {
  states: Array<{
    legacy_preflight: Record<string, unknown>;
    state: string;
  }>;
};

describe("v0.7 OpenClaw consumer against current storage states", () => {
  it("accepts current mixed and fully-v3 legacy bridge responses", () => {
    const bundlePath = process.env.ECHO_VEIL_N_MINUS_ONE_BUNDLE;
    expect(bundlePath).toBeTruthy();
    const bundle = JSON.parse(readFileSync(bundlePath!, "utf8")) as Bundle;
    expect(bundle.states.map((state) => state.state)).toEqual([
      "mixed-v2-v3",
      "fully-v3",
    ]);
    for (const state of bundle.states) {
      const response = state.legacy_preflight.openclaw;
      const context = parsePreflightContext(response, {
        expectedProfile: "echo-universal-qwen3-v1",
      });
      expect(context).toMatch(/^ECHO VEIL REQUIRED MEMORY PREFLIGHT/);
      expect(JSON.stringify(response)).not.toContain("record-envelope");
      expect(JSON.stringify(response)).not.toContain("record_envelope");
    }
  });
});
