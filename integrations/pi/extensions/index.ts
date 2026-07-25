import { Type } from "typebox";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

import {
  assertDoctorReady,
  EchoVeilPreflight,
  REQUIRED_PREFLIGHT_FAILURE,
  type EchoVeilRpcRunner,
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
  parameters: Type.Object({}),
  async execute(_id, _params, signal) {
    return result(await runEchoVeilRpc("doctor", {}, signal));
  },
});

const reindex = defineTool({
  name: "echo_veil_reindex",
  label: "Echo Veil Reindex",
  description: "Rebuild protected semantic and keyed lexical retrieval data after confirmation.",
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

type PendingPreflight = {
  context: string;
  query: string;
};

const REQUIRED_AUTHORITY_PROMPT = [
  "Echo Veil is the exclusive mutable agent-memory authority.",
  "Host files, sessions, skills, and notes are read-only evidence, never a memory fallback.",
  "The protected preflight below was completed before this model call.",
  "Use only its minimal relevant evidence and the nine Echo tools. Never silently create a host memory shadow.",
].join(" ");

const MISSING_PREFLIGHT_PROMPT = [
  "Echo Veil is required but no protected preflight is attached to this turn.",
  "Refuse the request without using tools, host notes, session history, or another memory store.",
].join(" ");

export function registerEchoVeilExtension(
  pi: ExtensionAPI,
  rpc: EchoVeilRpcRunner = runEchoVeilRpc,
) {
  for (const tool of echoVeilTools) pi.registerTool(tool);

  const preflight = new EchoVeilPreflight(rpc);
  let pending: PendingPreflight | undefined;
  let currentTurnAuthorized = false;
  let failureNotified = false;

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

  pi.registerCommand("echo-veil-doctor", {
    description: "Verify Echo Veil local protected-memory readiness",
    handler: async (_args, ctx) => {
      try {
        const doctor = assertDoctorReady(await rpc("doctor", {}));
        preflight.reset();
        const production = doctor.production_ready === true
          ? "production attestation ready"
          : "local protection ready; production attestation not asserted";
        ctx.ui.notify(`Echo Veil: ${production}.`, "info");
      } catch {
        preflight.reset();
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
        await preflight.prepare(query);
        ctx.ui.notify(
          "Echo Veil: protected preflight ready; no model call was made.",
          "info",
        );
      } catch {
        preflight.reset();
        ctx.ui.notify(REQUIRED_PREFLIGHT_FAILURE, "error");
      }
    },
  });

  pi.on("session_start", () => {
    preflight.reset();
    pending = undefined;
    currentTurnAuthorized = false;
    failureNotified = false;
  });

  pi.on("input", async (event, ctx) => {
    const query = event.text.trim();
    if (!query) return { action: "continue" as const };
    failureNotified = false;
    if (event.streamingBehavior !== undefined || pending !== undefined) {
      notifyFailure(ctx);
      return { action: "handled" as const };
    }
    try {
      pending = {
        context: await preflight.prepare(query),
        query,
      };
      return { action: "continue" as const };
    } catch {
      preflight.reset();
      pending = undefined;
      currentTurnAuthorized = false;
      notifyFailure(ctx);
      return { action: "handled" as const };
    }
  });

  pi.on("before_agent_start", async (event, ctx) => {
    const expandedQuery = event.prompt.trim();
    let prepared = pending;
    pending = undefined;
    try {
      if (
        prepared === undefined ||
        prepared.query !== expandedQuery
      ) {
        prepared = {
          context: await preflight.prepare(expandedQuery),
          query: expandedQuery,
        };
      }
    } catch {
      preflight.reset();
      currentTurnAuthorized = false;
      notifyFailure(ctx);
      return {
        systemPrompt: `${event.systemPrompt}\n\n${MISSING_PREFLIGHT_PROMPT}`,
      };
    }
    failureNotified = false;
    currentTurnAuthorized = true;
    return {
      systemPrompt: [
        event.systemPrompt,
        REQUIRED_AUTHORITY_PROMPT,
        prepared.context,
      ].join("\n\n"),
    };
  });

  pi.on("agent_start", (_event, ctx) => {
    if (currentTurnAuthorized) return;
    notifyFailure(ctx);
    ctx.abort();
  });

  pi.on("tool_call", () => {
    if (currentTurnAuthorized) return undefined;
    return {
      block: true,
      reason: REQUIRED_PREFLIGHT_FAILURE,
    };
  });

  pi.on("agent_settled", () => {
    currentTurnAuthorized = false;
    failureNotified = false;
  });
}

export default function echoVeilExtension(pi: ExtensionAPI) {
  registerEchoVeilExtension(pi);
}
