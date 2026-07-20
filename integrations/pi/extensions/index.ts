import { Type } from "typebox";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

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
  description: "Store one explicitly user-authorized durable memory locally.",
  parameters: Type.Object({
    topic: Type.String({ minLength: 1, maxLength: 512 }),
    payload: Type.String({ minLength: 1, maxLength: 100_000 }),
  }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("remember", params, signal));
  },
});

const recall = defineTool({
  name: "echo_veil_recall",
  label: "Echo Veil Recall",
  description: "Recall relevant local memories and respect confidence-gated results.",
  parameters: Type.Object({
    query: Type.String({ minLength: 1, maxLength: 20_000 }),
    topK: Type.Optional(Type.Integer({ minimum: 1, maximum: 20 })),
    minScore: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
    allowInferential: Type.Optional(Type.Boolean({
      description: "Use only after explicit user authorization for inferential recall.",
    })),
  }),
  async execute(_id, params, signal) {
    return result(await runEchoVeilRpc("recall", {
      query: params.query,
      top_k: params.topK ?? 5,
      min_score: params.minScore ?? 0.35,
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

const doctor = defineTool({
  name: "echo_veil_doctor",
  label: "Echo Veil Doctor",
  description: "Report local readiness and explicit production limitations.",
  parameters: Type.Object({}),
  async execute(_id, _params, signal) {
    return result(await runEchoVeilRpc("doctor", {}, signal));
  },
});

export const echoVeilTools = [remember, recall, forget, doctor];

export default function echoVeilExtension(pi: ExtensionAPI) {
  for (const tool of echoVeilTools) pi.registerTool(tool);
}
