import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { EchoVeilPreflight } from "../src/preflight.js";

type State = {
  doctor: unknown;
  pi_recall: unknown;
  state: string;
};

describe("v0.7 Pi consumer against current storage states", () => {
  it("accepts current doctor and recall without observing storage versions", async () => {
    const bundlePath = process.env.ECHO_VEIL_N_MINUS_ONE_BUNDLE;
    expect(bundlePath).toBeTruthy();
    const bundle = JSON.parse(readFileSync(bundlePath!, "utf8")) as {
      states: State[];
    };
    for (const state of bundle.states) {
      const preflight = new EchoVeilPreflight(async (action) => {
        if (action === "doctor") return state.doctor;
        if (action === "recall") return state.pi_recall;
        throw new Error("unexpected compatibility action");
      });
      const context = await preflight.prepare(
        "Which protected compatibility records are current?",
      );
      expect(context).toMatch(/^ECHO VEIL REQUIRED MEMORY PREFLIGHT/);
      expect(context).not.toContain("record-envelope");
      expect(context).not.toContain("record_envelope");
    }
  });
});
