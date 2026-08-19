import { randomUUID } from "node:crypto";
import { Type } from "typebox";
import {
  defineTool,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";

import { loadPiArtifactAuthority } from "../src/artifact.js";
import {
  assertDoctorReady,
  buildAvailabilityReport,
  digestModel,
  digestToolManifest,
  EchoVeilPreflight,
  payloadContainsContext,
  type PreflightBindings,
  REQUIRED_PREFLIGHT_FAILURE,
  type EchoVeilRpcRunner,
  type VerifiedPreflight,
  sha256Digest,
} from "../src/preflight.js";
import { runEchoVeilRpc } from "../src/runner.js";

function result(value: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
    details: value,
  };
}

const remember = defineTool({
  name: "echo_veil_remember",
  label: "Echo Veil Remember",
  description: "Store one compact authorized intent/outcome memory in a shielded semantic layer. Raw transcripts are Live-only.",
  executionMode: "sequential",
  parameters: Type.Object({
    topic: Type.String({ minLength: 1, maxLength: 512 }),
    payload: Type.String({ minLength: 1, maxLength: 20_000 }),
    effectiveAt: Type.Optional(Type.Number({ minimum: 0 })),
    supersedes: Type.Optional(Type.Array(
      Type.String({ minLength: 1, maxLength: 128 }),
      { maxItems: 20, uniqueItems: true },
    )),
    layer: Type.Optional(Type.Union([
      Type.Literal("live"),
      Type.Literal("short_term"),
      Type.Literal("contextual_logic"),
    ])),
    provenance: Type.Optional(Type.Array(
      Type.String({ minLength: 1, maxLength: 160 }),
      { minItems: 1, maxItems: 3, uniqueItems: true },
    )),
    promotionReason: Type.Optional(Type.String({ minLength: 1, maxLength: 240 })),
    expiresAt: Type.Optional(Type.Number({ minimum: 0 })),
    logicKind: Type.Optional(Type.Union([
      Type.Literal("causal_chain"),
      Type.Literal("contradiction_resolution"),
      Type.Literal("decision"),
      Type.Literal("principle"),
    ])),
    relatedIds: Type.Optional(Type.Array(
      Type.String({ minLength: 1, maxLength: 128 }),
      { minItems: 1, maxItems: 8, uniqueItems: true },
    )),
  }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("remember", {
      topic: params.topic,
      payload: params.payload,
      ...(params.effectiveAt === undefined ? {} : { effective_at: params.effectiveAt }),
      ...(params.supersedes === undefined ? {} : { supersedes: params.supersedes }),
      ...(params.layer === undefined ? {} : { layer: params.layer }),
      ...(params.provenance === undefined ? {} : { provenance: params.provenance }),
      ...(params.promotionReason === undefined
        ? {}
        : { promotion_reason: params.promotionReason }),
      ...(params.expiresAt === undefined ? {} : { expires_at: params.expiresAt }),
      ...(params.logicKind === undefined ? {} : { logic_kind: params.logicKind }),
      ...(params.relatedIds === undefined ? {} : { related_ids: params.relatedIds }),
    }, signal));
  },
});

const refreshLive = defineTool({
  name: "echo_veil_refresh_live",
  label: "Echo Veil Refresh Live",
  description: "Refresh current Live state. Changed content creates a shielded superseding version; unchanged content only renews protected Live metadata.",
  executionMode: "sequential",
  parameters: Type.Object({
    vineId: Type.String({ minLength: 1, maxLength: 128 }),
    payload: Type.String({ minLength: 1, maxLength: 20_000 }),
    provenance: Type.Optional(Type.Array(
      Type.String({ minLength: 1, maxLength: 160 }),
      { minItems: 1, maxItems: 3, uniqueItems: true },
    )),
    expiresAt: Type.Optional(Type.Number({ minimum: 0 })),
  }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("refresh_live", {
      vine_id: params.vineId,
      payload: params.payload,
      ...(params.provenance === undefined ? {} : { provenance: params.provenance }),
      ...(params.expiresAt === undefined ? {} : { expires_at: params.expiresAt }),
    }, signal));
  },
});

const promote = defineTool({
  name: "echo_veil_promote",
  label: "Echo Veil Promote",
  description: "Promote Live to Short-Term or Short-Term to Long-Term with explicit evidence. Long-Term requires durable provenance and compact seed content.",
  executionMode: "sequential",
  parameters: Type.Object({
    vineId: Type.String({ minLength: 1, maxLength: 128 }),
    targetLayer: Type.Union([
      Type.Literal("short_term"),
      Type.Literal("long_term"),
    ]),
    reason: Type.String({ minLength: 1, maxLength: 240 }),
    provenance: Type.Optional(Type.Array(
      Type.String({ minLength: 1, maxLength: 160 }),
      { minItems: 1, maxItems: 3, uniqueItems: true },
    )),
  }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("promote", {
      vine_id: params.vineId,
      target_layer: params.targetLayer,
      reason: params.reason,
      ...(params.provenance === undefined ? {} : { provenance: params.provenance }),
    }, signal));
  },
});

const recall = defineTool({
  name: "echo_veil_recall",
  label: "Echo Veil Recall",
  description: "Recall relevant local memories. Preserve both leading candidates when ranking_ambiguous=true and every returned group member when competing_memory_detected=true; never invent a resolution. Responses with degraded=true are conservative lexical hints, not semantic or authoritative recall.",
  executionMode: "sequential",
  parameters: Type.Object({
    query: Type.String({ minLength: 1, maxLength: 20_000 }),
    topK: Type.Optional(Type.Integer({ minimum: 2, maximum: 20 })),
    minScore: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
    asOf: Type.Optional(Type.Number({ minimum: 0 })),
    layers: Type.Optional(Type.Array(Type.Union([
      Type.Literal("live"),
      Type.Literal("short_term"),
      Type.Literal("long_term"),
      Type.Literal("contextual_logic"),
    ]), { minItems: 1, maxItems: 4, uniqueItems: true })),
    allowInferential: Type.Optional(Type.Boolean({
      description: "Use only after explicit user authorization for inferential recall.",
    })),
  }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("recall", {
      query: params.query,
      top_k: params.topK ?? 5,
      ...(params.minScore === undefined ? {} : { min_score: params.minScore }),
      ...(params.asOf === undefined ? {} : { as_of: params.asOf }),
      ...(params.layers === undefined ? {} : { layers: params.layers }),
      allow_inferential: params.allowInferential ?? false,
    }, signal));
  },
});

const context = defineTool({
  name: "echo_veil_context",
  label: "Echo Veil Context",
  description: "Trace confidence-checked Contextual Logic roots through bounded, authenticated outgoing evidence links. Linked evidence is not independently query-scored and no answer is synthesized.",
  executionMode: "sequential",
  parameters: Type.Object({
    query: Type.String({ minLength: 1, maxLength: 20_000 }),
    minScore: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
    asOf: Type.Optional(Type.Number({ minimum: 0 })),
    maxDepth: Type.Optional(Type.Integer({ minimum: 1, maximum: 2 })),
    maxRecords: Type.Optional(Type.Integer({ minimum: 1, maximum: 20 })),
    allowInferential: Type.Optional(Type.Boolean({
      description: "Use only after explicit user authorization for inferential recall.",
    })),
  }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("context", {
      query: params.query,
      ...(params.minScore === undefined ? {} : { min_score: params.minScore }),
      ...(params.asOf === undefined ? {} : { as_of: params.asOf }),
      max_depth: params.maxDepth ?? 1,
      max_records: params.maxRecords ?? 8,
      allow_inferential: params.allowInferential ?? false,
    }, signal));
  },
});

const forget = defineTool({
  name: "echo_veil_forget",
  label: "Echo Veil Forget",
  description: "Erase one local payload and its matching lifecycle/index state.",
  executionMode: "sequential",
  parameters: Type.Object({
    vineId: Type.String({ minLength: 1, maxLength: 128 }),
  }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("forget", { vine_id: params.vineId }, signal));
  },
});

const list = defineTool({
  name: "echo_veil_list",
  label: "Echo Veil List",
  description: "Return a bounded authenticated inventory for administrative recent-memory views. This is not semantic recall, does not mutate lifecycle state, and must not be injected wholesale into model context.",
  executionMode: "sequential",
  parameters: Type.Object({
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
    layers: Type.Optional(Type.Array(Type.Union([
      Type.Literal("live"),
      Type.Literal("short_term"),
      Type.Literal("long_term"),
      Type.Literal("contextual_logic"),
    ]), { minItems: 1, maxItems: 4, uniqueItems: true })),
    topicPrefix: Type.Optional(Type.String({ minLength: 1, maxLength: 512 })),
    newestFirst: Type.Optional(Type.Boolean()),
  }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("list", {
      limit: params.limit ?? 20,
      ...(params.layers === undefined ? {} : { layers: params.layers }),
      ...(params.topicPrefix === undefined
        ? {}
        : { topic_prefix: params.topicPrefix }),
      newest_first: params.newestFirst ?? true,
    }, signal));
  },
});

const doctor = defineTool({
  name: "echo_veil_doctor",
  label: "Echo Veil Doctor",
  description: "Report local readiness and explicit production limitations.",
  executionMode: "sequential",
  parameters: Type.Object({}),
  async execute(_id, _params, signal) {
    return result(await runEchoVeilRpc("doctor", {}, signal));
  },
});

const reindex = defineTool({
  name: "echo_veil_reindex",
  label: "Echo Veil Reindex",
  description: "Rebuild protected semantic and keyed lexical retrieval data after confirmation.",
  executionMode: "sequential",
  parameters: Type.Object({ confirm: Type.Literal(true) }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("reindex", { confirm: params.confirm }, signal));
  },
});

export const echoVeilTools = [
  remember,
  refreshLive,
  promote,
  recall,
  context,
  forget,
  list,
  doctor,
  reindex,
];

type ProtectedTurn = {
  bindings: PreflightBindings;
  injectedInSystemPrompt: boolean;
  receipt: VerifiedPreflight;
};

type TurnState =
  | "idle"
  | "input_pending"
  | "receipt_ready"
  | "agent_running"
  | "provider_pending"
  | "provider_authorized"
  | "between_turns"
  | "failed";

const MUTATING_ECHO_TOOLS = new Set([
  "echo_veil_forget",
  "echo_veil_promote",
  "echo_veil_refresh_live",
  "echo_veil_reindex",
  "echo_veil_remember",
]);
const INFERENTIAL_ECHO_TOOLS = new Set([
  "echo_veil_context",
  "echo_veil_recall",
]);

const REQUIRED_AUTHORITY_PROMPT = [
  "Echo Veil is the exclusive mutable agent-memory authority.",
  "Host files, sessions, skills, and notes are read-only evidence, never a memory fallback.",
  "A signed, query/model/tool/artifact/session/turn-bound preflight was verified before this model call.",
  "Use only its minimal relevant evidence and the nine Echo tools. Never silently create a host memory shadow.",
].join(" ");

const MISSING_PREFLIGHT_PROMPT = [
  "Echo Veil is required but no verified protected preflight is attached to this turn.",
  "Refuse the request without using tools, host notes, session history, or another memory store.",
].join(" ");

function opaqueSessionId(ctx: ExtensionContext): string {
  const raw = ctx.sessionManager.getSessionId();
  if (!raw) throw new Error("Pi session identity is unavailable");
  return `pi-session-${sha256Digest(raw).slice("sha256:".length, 39)}`;
}

function turnBindings(
  pi: ExtensionAPI,
  ctx: ExtensionContext,
  query: string,
  turnId: string,
  artifactAuthorityId: string,
): PreflightBindings {
  if (!ctx.model) throw new Error("Pi model identity is unavailable");
  return {
    artifactAuthorityId,
    modelDigest: digestModel(ctx.model),
    profile: process.env.ECHO_VEIL_PROFILE || "echo-universal-qwen3-v1",
    query,
    querySource: "current_user_prompt",
    scope: process.env.ECHO_VEIL_SCOPE || "local-user",
    sessionId: opaqueSessionId(ctx),
    toolManifestDigest: digestToolManifest(
      pi.getActiveTools(),
      pi.getAllTools(),
    ),
    turnId,
  };
}

export function registerEchoVeilExtension(
  pi: ExtensionAPI,
  rpc: EchoVeilRpcRunner = runEchoVeilRpc,
) {
  for (const tool of echoVeilTools) pi.registerTool(tool);

  let preflight: EchoVeilPreflight | undefined;
  let artifactAuthorityId: string | undefined;
  try {
    artifactAuthorityId = loadPiArtifactAuthority().artifact_authority_id;
    preflight = new EchoVeilPreflight(
      rpc,
      process.env.ECHO_VEIL_PREFLIGHT_AUTHORITY_ID ?? "",
    );
  } catch {
    // Keep the hooks registered so a missing or altered pin fails closed.
  }
  let protectedTurn: ProtectedTurn | undefined;
  let activeQuery: string | undefined;
  let state: TurnState = "idle";
  let failureNotified = false;
  const mutationConsents = new Set<string>();

  function notifyFailure(ctx: {
    ui: {
      notify(
        message: string,
        level?: "info" | "warning" | "error",
      ): void;
    };
  }): void {
    if (failureNotified) return;
    failureNotified = true;
    ctx.ui.notify(REQUIRED_PREFLIGHT_FAILURE, "error");
  }

  function failClosed(ctx: ExtensionContext): void {
    state = "failed";
    protectedTurn = undefined;
    mutationConsents.clear();
    notifyFailure(ctx);
    ctx.abort();
  }

  async function prepareTurn(
    query: string,
    ctx: ExtensionContext,
    injectedInSystemPrompt: boolean,
  ): Promise<ProtectedTurn> {
    if (!preflight || !artifactAuthorityId) {
      throw new Error("Pi protected artifact or receipt authority is unavailable");
    }
    const bindings = turnBindings(
      pi,
      ctx,
      query,
      `pi-turn-${randomUUID().replaceAll("-", "")}`,
      artifactAuthorityId,
    );
    return {
      bindings,
      injectedInSystemPrompt,
      receipt: await preflight.prepare(bindings, ctx.signal),
    };
  }

  pi.registerCommand("echo-veil-doctor", {
    description: "Verify Echo Veil local protected-memory readiness",
    handler: async (_args, ctx) => {
      try {
        const doctor = assertDoctorReady(await rpc("doctor", {}));
        const production = doctor.production_ready === true
          ? "production attestation ready"
          : "local protection ready; production attestation not asserted";
        ctx.ui.notify(`Echo Veil: ${production}.`, "info");
      } catch {
        ctx.ui.notify(REQUIRED_PREFLIGHT_FAILURE, "error");
      }
    },
  });

  pi.registerCommand("echo-veil-preflight", {
    description: "Run the protected Echo Veil recall/context preflight without a model call",
    handler: async (args, ctx) => {
      const query = args.trim();
      if (!query) {
        ctx.ui.notify(
          "Echo Veil preflight requires a bounded intent query.",
          "warning",
        );
        return;
      }
      try {
        await prepareTurn(query, ctx, false);
        ctx.ui.notify(
          "Echo Veil: signed protected preflight verified; no model call was made.",
          "info",
        );
      } catch {
        ctx.ui.notify(REQUIRED_PREFLIGHT_FAILURE, "error");
      }
    },
  });

  pi.registerCommand("echo-veil-availability", {
    description: "Manually inspect degraded read-only Echo availability without authorizing a model turn",
    handler: async (args, ctx) => {
      const query = args.trim();
      protectedTurn = undefined;
      state = "idle";
      if (!query) {
        ctx.ui.notify(
          "Echo Veil availability requires a bounded intent query.",
          "warning",
        );
        return;
      }
      try {
        const report = buildAvailabilityReport(await rpc(
          "availability_recall",
          { query, top_k: 5 },
        ));
        ctx.ui.notify(report, "warning");
      } catch {
        ctx.ui.notify(
          "Echo Veil Always-Available retrieval failed closed; no model turn or memory mutation was authorized.",
          "error",
        );
      }
    },
  });

  pi.on("session_start", () => {
    preflight?.reset();
    protectedTurn = undefined;
    activeQuery = undefined;
    state = "idle";
    failureNotified = false;
    mutationConsents.clear();
  });

  pi.on("input", async (event, ctx) => {
    const query = event.text.trim();
    if (!query) return { action: "continue" as const };
    failureNotified = false;
    if (event.streamingBehavior !== undefined || state !== "idle") {
      notifyFailure(ctx);
      return { action: "handled" as const };
    }
    if (!preflight || !artifactAuthorityId) {
      notifyFailure(ctx);
      return { action: "handled" as const };
    }
    state = "input_pending";
    activeQuery = query;
    try {
      protectedTurn = await prepareTurn(query, ctx, true);
      state = "receipt_ready";
      return { action: "continue" as const };
    } catch {
      state = "failed";
      protectedTurn = undefined;
      notifyFailure(ctx);
      return { action: "handled" as const };
    }
  });

  pi.on("before_agent_start", async (event, ctx) => {
    const expandedQuery = event.prompt.trim();
    if (state !== "receipt_ready" && state !== "idle") {
      failClosed(ctx);
      return {
        systemPrompt: `${event.systemPrompt}\n\n${MISSING_PREFLIGHT_PROMPT}`,
      };
    }
    try {
      if (
        state === "idle" ||
        !protectedTurn ||
        activeQuery !== expandedQuery
      ) {
        protectedTurn = await prepareTurn(expandedQuery, ctx, true);
      }
      activeQuery = expandedQuery;
    } catch {
      failClosed(ctx);
      return {
        systemPrompt: `${event.systemPrompt}\n\n${MISSING_PREFLIGHT_PROMPT}`,
      };
    }
    failureNotified = false;
    state = "receipt_ready";
    return {
      systemPrompt: [
        event.systemPrompt,
        REQUIRED_AUTHORITY_PROMPT,
        protectedTurn.receipt.context,
      ].join("\n\n"),
    };
  });

  pi.on("agent_start", (_event, ctx) => {
    if (state === "receipt_ready" && protectedTurn) {
      state = "agent_running";
      return;
    }
    failClosed(ctx);
  });

  pi.on("turn_start", async (_event, ctx) => {
    try {
      if (state === "agent_running" && protectedTurn) {
        state = "provider_pending";
        return;
      }
      if (state !== "between_turns" || !activeQuery) {
        throw new Error("Pi turn state is invalid");
      }
      protectedTurn = await prepareTurn(activeQuery, ctx, false);
      state = "provider_pending";
    } catch {
      failClosed(ctx);
    }
  });

  pi.on("context", (event, ctx) => {
    if (state !== "provider_pending" || !protectedTurn) {
      failClosed(ctx);
      return { messages: [] };
    }
    if (protectedTurn.injectedInSystemPrompt) return undefined;
    const message = {
      role: "custom",
      customType: "echo-veil-preflight",
      content: [{ type: "text", text: protectedTurn.receipt.context }],
      display: false,
      timestamp: Date.now(),
    } as typeof event.messages[number];
    return { messages: [...event.messages, message] };
  });

  pi.on("before_provider_request", (event, ctx) => {
    try {
      if (
        state !== "provider_pending" ||
        !protectedTurn ||
        !preflight ||
        !artifactAuthorityId ||
        !activeQuery
      ) {
        throw new Error("Pi provider boundary is unauthorized");
      }
      const currentBindings = turnBindings(
        pi,
        ctx,
        activeQuery,
        protectedTurn.bindings.turnId,
        artifactAuthorityId,
      );
      preflight.consume(protectedTurn.receipt, currentBindings);
      if (!payloadContainsContext(event.payload, protectedTurn.receipt.context)) {
        throw new Error("Pi provider payload omitted protected evidence");
      }
      state = "provider_authorized";
      return undefined;
    } catch {
      failClosed(ctx);
      return {};
    }
  });

  pi.on("tool_call", async (event, ctx) => {
    if (state !== "provider_authorized") {
      return {
        block: true,
        reason: REQUIRED_PREFLIGHT_FAILURE,
        terminate: true,
      };
    }
    const toolInput = event.input as Record<string, unknown>;
    const inferential = INFERENTIAL_ECHO_TOOLS.has(event.toolName) &&
      toolInput.allowInferential === true;
    if (!MUTATING_ECHO_TOOLS.has(event.toolName) && !inferential) {
      return undefined;
    }
    if (!ctx.hasUI || mutationConsents.has(event.toolCallId)) {
      return {
        block: true,
        reason: "Echo Veil mutation requires fresh one-use user consent.",
        terminate: true,
      };
    }
    const confirmed = await ctx.ui.confirm(
      "Echo Veil protected one-use authorization",
      `Allow ${event.toolName} once for this exact ${inferential ? "inferential recall" : "mutation"} call?`,
    );
    if (!confirmed) {
      return {
        block: true,
        reason: "Echo Veil mutation was not authorized by the user.",
        terminate: true,
      };
    }
    mutationConsents.add(event.toolCallId);
    return undefined;
  });

  pi.on("tool_execution_end", (event) => {
    mutationConsents.delete(event.toolCallId);
  });

  pi.on("turn_end", (_event, ctx) => {
    if (state !== "provider_authorized") {
      failClosed(ctx);
      return;
    }
    mutationConsents.clear();
    protectedTurn = undefined;
    state = "between_turns";
  });

  pi.on("agent_settled", () => {
    protectedTurn = undefined;
    activeQuery = undefined;
    state = "idle";
    failureNotified = false;
    mutationConsents.clear();
  });
}

export default function echoVeilExtension(pi: ExtensionAPI) {
  registerEchoVeilExtension(pi);
}
