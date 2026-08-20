import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import entry, {
  addRpcTelemetry,
  buildChildEnvironment,
  buildEchoVeilPromptSection,
  buildEchoVeilTools,
  buildInvocation,
  createOpenClawPreflightHandlers,
  hasRequiredOpenClawHookPolicy,
  parsePreflightContext,
  parseCapabilitiesV1,
  registerEchoVeil,
} from "./index.js";

function protocolFixture(): Record<string, unknown> {
  return JSON.parse(readFileSync(
    fileURLToPath(new URL(
      "../../../protocol/fixtures/compatibility-v1.json",
      import.meta.url,
    )),
    "utf8",
  )) as Record<string, unknown>;
}

describe("echo-veil OpenClaw plugin", () => {
  it("consumes the shared legacy bridge and optional capabilities fixtures", () => {
    const fixture = protocolFixture();
    const legacy = fixture.legacy_preflight_cases as Record<
      string,
      Record<string, unknown>
    >;
    const openclaw = legacy.openclaw?.response;
    expect(parsePreflightContext(openclaw, {
      expectedProfile: "echo-universal-qwen3-v1",
    })).toContain("MEMORY_EVIDENCE_JSON=");

    const cases = fixture.capabilities_cases as Record<
      string,
      Record<string, unknown>
    >;
    expect(parseCapabilitiesV1(cases.absent?.value)).toBeNull();
    expect(parseCapabilitiesV1(cases.valid?.value)?.schema)
      .toBe("echo-veil-capabilities-v1");
    expect(parseCapabilitiesV1(cases.valid_documented_additions?.value)
      ?.remediation_codes).toEqual(["EV-BACKUP-UNVERIFIED"]);
    const unknown = structuredClone(
      cases.unknown_schema?.value,
    ) as Record<string, unknown>;
    unknown.schema = "echo-veil-capabilities-v2";
    expect(() => parseCapabilitiesV1(unknown)).toThrow(
      "capabilities_v1",
    );
  });
  it("declares the native tool contract", () => {
    const tools = buildEchoVeilTools({});
    expect(tools.map((tool) => tool.name)).toEqual([
      "echo_veil_remember",
      "echo_veil_refresh_live",
      "echo_veil_promote",
      "echo_veil_recall",
      "echo_veil_context",
      "echo_veil_forget",
      "echo_veil_list",
      "echo_veil_doctor",
      "echo_veil_reindex",
    ]);
    const recall = tools.find((tool) => tool.name === "echo_veil_recall");
    const context = tools.find((tool) => tool.name === "echo_veil_context");
    const remember = tools.find((tool) => tool.name === "echo_veil_remember");
    const refresh = tools.find((tool) => tool.name === "echo_veil_refresh_live");
    const list = tools.find((tool) => tool.name === "echo_veil_list");
    expect(JSON.stringify(recall?.parameters)).toContain('"minimum":2');
    expect(JSON.stringify(recall?.parameters)).toContain('"long_term"');
    expect(JSON.stringify(context?.parameters)).toContain('"maximum":20');
    expect(JSON.stringify(remember?.parameters)).toContain('"contextual_logic"');
    expect(JSON.stringify(remember?.parameters)).toContain('"provenance"');
    expect(JSON.stringify(remember?.parameters)).toContain('"maxItems":3');
    expect(JSON.stringify(remember?.parameters)).not.toContain('"long_term"');
    expect(JSON.stringify(remember?.parameters)).toContain('"maxLength":20000');
    expect(JSON.stringify(refresh?.parameters)).toContain('"maxLength":20000');
    expect(remember?.description).toContain("Raw transcripts are Live-only");
    expect(refresh?.description).toContain("shielded superseding version");
    expect(recall?.description).toContain("not semantic or authoritative recall");
    expect(recall?.description).toContain("competing_memory_detected=true");
    expect(recall?.description).toContain("never invent a resolution");
    expect(context?.description).toContain("not independently query-scored");
    expect(JSON.stringify(list?.parameters)).toContain('"maximum":100');
    expect(list?.description).toContain("not semantic recall");
  });

  it("registers the exclusive memory capability and all nine tools", () => {
    const registered: Array<{
      name: string;
      optional: boolean | undefined;
    }> = [];
    let promptBuilder:
      | ((params: { availableTools: Set<string> }) => string[])
      | undefined;
    const hooks: Array<{ name: string; priority?: number; timeoutMs?: number }> = [];
    registerEchoVeil({
      config: {
        plugins: {
          entries: {
            "echo-veil": {
              hooks: {
                allowConversationAccess: true,
                allowPromptInjection: true,
              },
            },
          },
        },
      },
      pluginConfig: { profile: "shared" },
      on: (name, _handler, options) => {
        hooks.push({ name, ...options });
      },
      registerTool: (tool, options) => {
        registered.push({ name: tool.name, optional: options?.optional });
      },
      registerMemoryCapability: (capability) => {
        promptBuilder = capability.promptBuilder;
      },
    });

    expect(registered).toHaveLength(9);
    expect(registered.filter((item) => item.optional)).toHaveLength(5);
    expect(hooks).toEqual([
      { name: "before_agent_reply", priority: 1_000 },
      { name: "before_prompt_build", priority: 1_000, timeoutMs: 120_000 },
      { name: "before_agent_run", priority: 1_000, timeoutMs: 5_000 },
    ]);
    expect(promptBuilder).toBe(buildEchoVeilPromptSection);
    expect(entry.register).toBe(registerEchoVeil);
    const availableTools = new Set(registered.map((item) => item.name));
    const prompt = promptBuilder?.({ availableTools }).join("\n") ?? "";
    expect(prompt).toContain("exclusive mutable agent-memory authority");
    expect(prompt).toContain("echo_veil_doctor");
    expect(prompt).toContain("echo_veil_recall");
    expect(prompt).toContain("echo_veil_context");
    expect(prompt).toContain("ranking_ambiguous=true");
    expect(prompt).toContain("competing_memory_detected=true");
    expect(prompt).toContain("degraded=true");
    expect(prompt).toContain("Long-Term");
    expect(prompt).toContain("Contextual Logic");
    expect(prompt).toContain("host plaintext fallback");
  });

  it("keeps the memory authority fail closed when required tools are absent", () => {
    const prompt = buildEchoVeilPromptSection({
      availableTools: new Set(["echo_veil_recall"]),
    }).join("\n");

    expect(prompt).toContain("exclusive mutable agent-memory authority");
    expect(prompt).toContain("Required Echo Veil memory tools are unavailable");
    expect(prompt).toContain("do not consult or write a host plaintext fallback");
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
    expect(invocation.env.ECHO_VEIL_SCOPE).toBe("local-user");
    expect(invocation.env.ECHO_VEIL_CALLER).toBe("openclaw");
    expect(invocation.env.ECHO_VEIL_EMBEDDER).toBe("ollama");
    expect(invocation.env.ECHO_VEIL_EMBEDDING_MODEL).toBe("qwen3-embedding:latest");
    expect(invocation.env.ECHO_VEIL_EMBEDDING_DIMENSION).toBe("1024");
    expect(invocation.env.ECHO_VEIL_AVAILABILITY_LAYER).toBe("true");
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
    expect(invocation.env.ECHO_VEIL_PROFILE).toBe("echo-universal-qwen3-v1");
    expect(invocation.env.ECHO_VEIL_CALLER).toBe("openclaw");
  });

  it("adds bounded fresh-process latency telemetry without replacing recall fields", () => {
    expect(addRpcTelemetry({ degraded: true }, 1_891.237)).toEqual({
      degraded: true,
      host_transport: {
        host: "openclaw",
        invocation: "fresh-process-rpc",
        elapsed_ms: 1_891.24,
      },
    });
  });

  it("withholds unrelated host credentials from the child process", () => {
    const env = buildChildEnvironment({
      PATH: "/usr/bin",
      OPENAI_API_KEY: "must-not-cross-boundary",
      ECHO_VEIL_CRYPTO_KEY: "must-not-cross-boundary",
      ECHO_VEIL_PROFILE: "shared",
    });

    expect(env.PATH).toBe("/usr/bin");
    expect(env.ECHO_VEIL_PROFILE).toBe("shared");
    expect(env.OPENAI_API_KEY).toBeUndefined();
    expect(env.ECHO_VEIL_CRYPTO_KEY).toBeUndefined();
  });

  it("attests injected protected context before allowing a model turn", async () => {
    const calls: Array<{ action: string; argumentsValue: Record<string, unknown> }> = [];
    const protectedContext = [
      "ECHO VEIL REQUIRED MEMORY PREFLIGHT",
      "MEMORY_EVIDENCE_JSON={\"authority\":\"echo-veil\"}",
    ].join("\n");
    const handlers = createOpenClawPreflightHandlers(
      { profile: "echo-universal-qwen3-v1" },
      {
        rpc: async (action, argumentsValue) => {
          calls.push({ action, argumentsValue });
          return {
            preflight_ready: true,
            memory_authority: "echo-veil",
            host: "openclaw",
            profile: "echo-universal-qwen3-v1",
            query_source: "current_user_prompt",
            semantic: true,
            context: protectedContext,
          };
        },
        now: () => 1_000,
        token: () => "a".repeat(64),
      },
    );

    const claim = await handlers.beforeAgentReply(
      { cleanedBody: "What did we decide?" },
      { sessionId: "session-1", sessionKey: "agent:main" },
    );
    const injection = await handlers.beforePromptBuild(
      { prompt: "What did we decide?", messages: [] },
      { runId: "run-1", sessionId: "session-1", sessionKey: "agent:main" },
    );
    const decision = handlers.beforeAgentRun(
      {
        prompt: `${injection.prependContext}\n\nWhat did we decide?`,
        messages: [],
      },
      { runId: "run-1", sessionId: "session-1", sessionKey: "agent:main" },
    );

    expect(calls).toEqual([
      {
        action: "preflight",
        argumentsValue: {
          query: "What did we decide?",
          expected_profile: "echo-universal-qwen3-v1",
          query_source: "current_user_prompt",
        },
      },
    ]);
    expect(claim).toEqual({ handled: false });
    expect(injection.prependContext).toContain(
      `ECHO_VEIL_TURN_ATTESTATION=${"a".repeat(64)}`,
    );
    expect(decision).toEqual({ outcome: "pass" });
    expect(
      handlers.beforeAgentRun(
        { prompt: injection.prependContext, messages: [] },
        { runId: "run-1" },
      ),
    ).toMatchObject({ outcome: "block", category: "memory_preflight_unavailable" });
  });

  it("blocks when prompt injection is missing, expired, or never completed", async () => {
    let clock = 1_000;
    const response = {
      preflight_ready: true,
      memory_authority: "echo-veil",
      host: "openclaw",
      profile: "echo-universal-qwen3-v1",
      query_source: "current_user_prompt",
      semantic: true,
      context: "ECHO VEIL REQUIRED MEMORY PREFLIGHT\nMEMORY_EVIDENCE_JSON={}",
    };
    const handlers = createOpenClawPreflightHandlers(
      {},
      {
        rpc: async () => response,
        now: () => clock,
        token: () => "b".repeat(64),
      },
    );

    await handlers.beforeAgentReply(
      { cleanedBody: "Protected request" },
      { runId: "missing-injection" },
    );
    expect(
      handlers.beforeAgentRun(
        { prompt: "Protected request", messages: [] },
        { runId: "missing-injection" },
      ),
    ).toMatchObject({ outcome: "block" });

    await handlers.beforeAgentReply(
      { cleanedBody: "Protected request" },
      { runId: "expired" },
    );
    const injected = await handlers.beforePromptBuild(
      { prompt: "Protected request", messages: [] },
      { runId: "expired" },
    );
    clock += 300_001;
    expect(
      handlers.beforeAgentRun(
        { prompt: injected.prependContext, messages: [] },
        { runId: "expired" },
      ),
    ).toMatchObject({ outcome: "block" });
    expect(
      handlers.beforeAgentRun(
        { prompt: "No preflight", messages: [] },
        { runId: "never-started" },
      ),
    ).toMatchObject({ outcome: "block" });
  });

  it("binds a host-enveloped prompt by the stable session identity", async () => {
    const handlers = createOpenClawPreflightHandlers(
      {},
      {
        rpc: async () => ({
          preflight_ready: true,
          memory_authority: "echo-veil",
          host: "openclaw",
          profile: "echo-universal-qwen3-v1",
          query_source: "current_user_prompt",
          semantic: true,
          context: "ECHO VEIL REQUIRED MEMORY PREFLIGHT\nMEMORY_EVIDENCE_JSON={}",
        }),
        token: () => "c".repeat(64),
      },
    );
    await handlers.beforeAgentReply(
      { cleanedBody: "Protected request" },
      { sessionId: "session-1", sessionKey: "agent:main" },
    );
    const injected = await handlers.beforePromptBuild(
      {
        prompt: "[Friday 03:50] Protected request",
        messages: [],
      },
      {
        runId: "run-1",
        sessionId: "session-1",
        sessionKey: "agent:main",
      },
    );
    expect(injected.prependContext).toContain(
      `ECHO_VEIL_TURN_ATTESTATION=${"c".repeat(64)}`,
    );
  });

  it("preflights from prompt construction when the early reply hook is skipped", async () => {
    const handlers = createOpenClawPreflightHandlers(
      {},
      {
        rpc: async () => ({
          preflight_ready: true,
          memory_authority: "echo-veil",
          host: "openclaw",
          profile: "echo-universal-qwen3-v1",
          query_source: "current_user_prompt",
          semantic: true,
          context: "ECHO VEIL REQUIRED MEMORY PREFLIGHT\nMEMORY_EVIDENCE_JSON={}",
        }),
        token: () => "d".repeat(64),
      },
    );
    const injected = await handlers.beforePromptBuild(
      { prompt: "Fast bootstrap request", messages: [] },
      { runId: "fast-run" },
    );
    expect(
      handlers.beforeAgentRun(
        {
          prompt: `${injected.prependContext}\nFast bootstrap request`,
          messages: [],
        },
        { runId: "fast-run" },
      ),
    ).toEqual({ outcome: "pass" });
  });

  it("short-circuits the model when Echo is unavailable or hook policy is unsafe", async () => {
    const unavailable = createOpenClawPreflightHandlers(
      {},
      {
        rpc: async () => {
          throw new Error("private backend detail");
        },
      },
    );
    const unavailableResult = await unavailable.beforeAgentReply(
      { cleanedBody: "Protected request" },
      { runId: "outage" },
    );
    expect(unavailableResult).toEqual({
      handled: true,
      reply: {
        text: "Echo Veil required preflight is unavailable. The model turn was blocked; no host memory fallback was used.",
      },
      reason: "memory_preflight_unavailable",
    });
    expect(JSON.stringify(unavailableResult)).not.toContain("private backend detail");
    const missingInjection = await unavailable.beforePromptBuild(
      { prompt: "Protected request", messages: [] },
      { runId: "outage-fast-path" },
    );
    expect(missingInjection.prependSystemContext).toContain(
      "Do not answer the user request",
    );
    expect(
      unavailable.beforeAgentRun(
        { prompt: "Protected request", messages: [] },
        { runId: "outage-fast-path" },
      ),
    ).toMatchObject({ outcome: "block" });

    let calls = 0;
    let policyReady = false;
    const unsafePolicy = createOpenClawPreflightHandlers(
      {},
      {
        hookPolicyReady: () => policyReady,
        rpc: async () => {
          calls += 1;
          throw new Error("synthetic outage");
        },
      },
    );
    expect(
      await unsafePolicy.beforeAgentReply(
        { cleanedBody: "Protected request" },
        { runId: "unsafe-policy" },
      ),
    ).toMatchObject({ handled: true });
    expect(calls).toBe(0);
    policyReady = true;
    expect(
      await unsafePolicy.beforeAgentReply(
        { cleanedBody: "Protected request" },
        { runId: "unsafe-policy" },
      ),
    ).toMatchObject({ handled: true });
    expect(calls).toBe(1);
    policyReady = false;
    expect(
      await unsafePolicy.beforePromptBuild(
        { prompt: "Protected request", messages: [] },
        { runId: "unsafe-policy" },
      ),
    ).toHaveProperty("prependSystemContext");
    expect(
      unsafePolicy.beforeAgentRun(
        { prompt: "Protected request", messages: [] },
        { runId: "unsafe-policy" },
      ),
    ).toMatchObject({ outcome: "block" });
    expect(calls).toBe(1);
  });

  it("requires exclusive Echo routing, both hook permissions, and native session memory off", () => {
    expect(
      hasRequiredOpenClawHookPolicy({
        plugins: {
          slots: { memory: "echo-veil" },
          entries: {
            "echo-veil": {
              hooks: {
                allowConversationAccess: true,
                allowPromptInjection: true,
              },
            },
          },
        },
        hooks: {
          internal: {
            entries: {
              "session-memory": { enabled: false },
            },
          },
        },
      }),
    ).toBe(true);
    expect(
      hasRequiredOpenClawHookPolicy({
        plugins: {
          slots: { memory: "echo-veil" },
          entries: {
            "echo-veil": {
              hooks: { allowConversationAccess: true },
            },
          },
        },
        hooks: {
          internal: {
            entries: {
              "session-memory": { enabled: false },
            },
          },
        },
      }),
    ).toBe(false);
    expect(
      hasRequiredOpenClawHookPolicy({
        plugins: {
          slots: { memory: "echo-veil" },
          entries: {
            "echo-veil": {
              hooks: {
                allowConversationAccess: true,
                allowPromptInjection: true,
              },
            },
          },
        },
        hooks: {
          internal: {
            entries: {
              "session-memory": { enabled: true },
            },
          },
        },
      }),
    ).toBe(false);
    expect(
      hasRequiredOpenClawHookPolicy({
        plugins: {
          slots: { memory: "memory-core" },
          entries: {
            "echo-veil": {
              hooks: {
                allowConversationAccess: true,
                allowPromptInjection: true,
              },
            },
          },
        },
        hooks: {
          internal: {
            entries: {
              "session-memory": { enabled: false },
            },
          },
        },
      }),
    ).toBe(false);
  });

  it("rejects a preflight response that is degraded or bound to another host", () => {
    expect(() =>
      parsePreflightContext(
        {
          preflight_ready: true,
          memory_authority: "echo-veil",
          host: "droid",
          profile: "echo-universal-qwen3-v1",
          query_source: "current_user_prompt",
          semantic: true,
          context: "ECHO VEIL REQUIRED MEMORY PREFLIGHT",
        },
        { expectedProfile: "echo-universal-qwen3-v1" },
      ),
    ).toThrow("protected contract");
  });
});
