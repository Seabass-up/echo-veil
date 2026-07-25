import assert from "node:assert/strict"
import test from "node:test"

import { EchoVeilShield } from "../.opencode/plugins/echo-veil-shield.js"

const FAILURE =
  "Echo Veil required preflight is unavailable. The OpenCode model turn was blocked; no host memory fallback was used."

function result(querySource = "current_user_prompt") {
  return {
    preflight_ready: true,
    memory_authority: "echo-veil",
    host: "opencode",
    profile: "echo-universal-qwen3-v1",
    query_source: querySource,
    semantic: true,
    context:
      "ECHO VEIL REQUIRED MEMORY PREFLIGHT\nMEMORY_EVIDENCE_JSON={\"results\":[]}",
  }
}

function messageOutput(text = "Recall the current protected state.") {
  return {
    message: { id: "message-1", sessionID: "session-1" },
    parts: [
      {
        id: "part-1",
        sessionID: "session-1",
        messageID: "message-1",
        type: "text",
        text,
      },
    ],
  }
}

test("root turns receive protected context before chat parameters are built", async () => {
  const requests = []
  const hooks = await EchoVeilShield({
    __echoVeilTestRunner: async (action, argumentsValue) => {
      requests.push({ action, argumentsValue })
      return result(argumentsValue.query_source)
    },
  })
  const output = messageOutput()

  await hooks["chat.message"]({ sessionID: "session-1" }, output)
  await hooks["chat.params"](
    { sessionID: "session-1", message: { id: "message-1" } },
    {},
  )

  assert.equal(requests.length, 1)
  assert.equal(requests[0].action, "preflight")
  assert.equal(
    requests[0].argumentsValue.query,
    "Recall the current protected state.",
  )
  assert.match(
    output.parts[0].text,
    /ECHO_VEIL_PROTECTED_OPENCODE_CONTEXT_BEGIN/,
  )
  assert.match(output.parts[0].text, /CURRENT_OPENCODE_PROMPT_BEGIN/)
})

test("an Echo outage stops before the simulated provider consumes tokens", async () => {
  let providerCalls = 0
  let tokens = 0
  const hooks = await EchoVeilShield({
    __echoVeilTestRunner: async () => {
      throw new Error("private outage detail")
    },
  })

  await assert.rejects(
    hooks["chat.message"](
      { sessionID: "session-1" },
      messageOutput(),
    ).then(() => {
      providerCalls += 1
      tokens += 100
    }),
    new RegExp(FAILURE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  )

  assert.equal(providerCalls, 0)
  assert.equal(tokens, 0)
})

test("chat parameter construction fails closed without a matching preflight", async () => {
  const hooks = await EchoVeilShield({
    __echoVeilTestRunner: async () => result(),
  })

  await assert.rejects(
    hooks["chat.params"](
      { sessionID: "session-1", message: { id: "unqualified" } },
      {},
    ),
    new RegExp(FAILURE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  )
})

test("Task spawns preserve arguments and prepend task-specific recall", async () => {
  const requests = []
  const hooks = await EchoVeilShield({
    __echoVeilTestRunner: async (_action, argumentsValue) => {
      requests.push(argumentsValue)
      return result(argumentsValue.query_source)
    },
  })
  const output = {
    args: {
      prompt: "Why is Echo the selected memory authority?",
      description: "review the decision",
      subagent_type: "general",
    },
  }

  await hooks["tool.execute.before"](
    { tool: "task", sessionID: "session-1", callID: "call-1" },
    output,
  )

  assert.equal(requests[0].query_source, "subagent_task")
  assert.equal(output.args.description, "review the decision")
  assert.equal(output.args.subagent_type, "general")
  assert.match(
    output.args.prompt,
    /ECHO_VEIL_PROTECTED_OPENCODE_CONTEXT_BEGIN/,
  )
  assert.match(output.args.prompt, /Why is Echo the selected memory authority\?/)
})

test("Task spawn failure is generic and leaves the original arguments intact", async () => {
  const hooks = await EchoVeilShield({
    __echoVeilTestRunner: async () => {
      throw new Error("/private/path/secret")
    },
  })
  const output = {
    args: {
      prompt: "Inspect the protected adapter.",
      description: "safe description",
    },
  }

  await assert.rejects(
    hooks["tool.execute.before"](
      { tool: "task", sessionID: "session-1", callID: "call-1" },
      output,
    ),
    new RegExp(FAILURE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  )

  assert.deepEqual(output.args, {
    prompt: "Inspect the protected adapter.",
    description: "safe description",
  })
})

test("automatic post-compaction model continuation is disabled", async () => {
  const hooks = await EchoVeilShield({
    __echoVeilTestRunner: async () => result(),
  })
  const output = { enabled: true }

  await hooks["experimental.compaction.autocontinue"]({}, output)

  assert.equal(output.enabled, false)
})

test("the built-in outage control fails closed without invoking the child", async () => {
  const previous = process.env.ECHO_VEIL_FORCE_PREFLIGHT_FAILURE
  let childCalls = 0
  process.env.ECHO_VEIL_FORCE_PREFLIGHT_FAILURE = "1"
  try {
    const hooks = await EchoVeilShield({
      __echoVeilTestRunner: async () => {
        childCalls += 1
        return result()
      },
    })

    await assert.rejects(
      hooks["chat.message"](
        { sessionID: "session-1" },
        messageOutput(),
      ),
      new RegExp(FAILURE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    )
    assert.equal(childCalls, 0)
  } finally {
    if (previous === undefined) {
      delete process.env.ECHO_VEIL_FORCE_PREFLIGHT_FAILURE
    } else {
      process.env.ECHO_VEIL_FORCE_PREFLIGHT_FAILURE = previous
    }
  }
})

test("the Task-only outage control leaves root preflight healthy", async () => {
  const previous = process.env.ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE
  let childCalls = 0
  process.env.ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE = "1"
  try {
    const hooks = await EchoVeilShield({
      __echoVeilTestRunner: async (_action, argumentsValue) => {
        childCalls += 1
        return result(argumentsValue.query_source)
      },
    })
    const output = messageOutput()

    await hooks["chat.message"]({ sessionID: "session-1" }, output)
    await hooks["chat.params"](
      { sessionID: "session-1", message: { id: "message-1" } },
      {},
    )

    assert.equal(childCalls, 1)
    assert.match(
      output.parts[0].text,
      /ECHO_VEIL_PROTECTED_OPENCODE_CONTEXT_BEGIN/,
    )
  } finally {
    if (previous === undefined) {
      delete process.env.ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE
    } else {
      process.env.ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE = previous
    }
  }
})

test("the Task-only outage control denies before invoking the child", async () => {
  const previous = process.env.ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE
  let childCalls = 0
  process.env.ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE = "1"
  try {
    const hooks = await EchoVeilShield({
      __echoVeilTestRunner: async () => {
        childCalls += 1
        return result("subagent_task")
      },
    })
    const output = {
      args: {
        prompt: "Run the installed Task smoke.",
        description: "spawn qualification",
        subagent_type: "general",
      },
    }

    await assert.rejects(
      hooks["tool.execute.before"](
        { tool: "Task", sessionID: "session-1", callID: "call-1" },
        output,
      ),
      new RegExp(FAILURE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    )

    assert.equal(childCalls, 0)
    assert.deepEqual(output.args, {
      prompt: "Run the installed Task smoke.",
      description: "spawn qualification",
      subagent_type: "general",
    })
  } finally {
    if (previous === undefined) {
      delete process.env.ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE
    } else {
      process.env.ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE = previous
    }
  }
})
