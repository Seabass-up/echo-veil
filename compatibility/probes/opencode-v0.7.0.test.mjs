import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import test from "node:test"

import { EchoVeilShield } from "../.opencode/plugins/echo-veil-shield.js"

test("v0.7 OpenCode accepts current mixed and v3 preflight responses", async () => {
  const bundle = JSON.parse(
    await readFile(process.env.ECHO_VEIL_N_MINUS_ONE_BUNDLE, "utf8"),
  )
  for (const state of bundle.states) {
    const response = state.legacy_preflight.opencode
    const hooks = await EchoVeilShield({
      __echoVeilTestRunner: async (action, argumentsValue) => {
        assert.equal(action, "preflight")
        assert.equal(argumentsValue.query_source, "current_user_prompt")
        return response
      },
    })
    const output = {
      message: { id: `message-${state.state}`, sessionID: "compatibility" },
      parts: [
        {
          id: `part-${state.state}`,
          messageID: `message-${state.state}`,
          sessionID: "compatibility",
          text: "Which protected compatibility records are current?",
          type: "text",
        },
      ],
    }
    await hooks["chat.message"]({ sessionID: "compatibility" }, output)
    await hooks["chat.params"](
      {
        message: { id: `message-${state.state}` },
        sessionID: "compatibility",
      },
      {},
    )
    assert.match(output.parts[0].text, /ECHO_VEIL_PROTECTED_OPENCODE_CONTEXT_BEGIN/)
    assert.doesNotMatch(output.parts[0].text, /record[-_]envelope/)
  }
})
