---
name: echo-veil
description: Check Echo Veil readiness and explain its safe memory boundary in Mercury.
version: 0.4.0
category: developer-tools
intents:
  - echo veil memory
  - check echo veil
tags:
  - memory
  - privacy
  - echo-veil
allowed-tools:
  - run_command
---

# Echo Veil for Mercury

Mercury currently documents Agent Skills but not arbitrary MCP or structured
custom-tool registration. This skill therefore exposes only a safe readiness
check. It must not send memory topics, payloads, queries, identifiers, keys, or
other user content through `run_command`, command arguments, shell pipelines,
temporary files, URLs, logs, or environment variables.

When the user asks to check Echo Veil, run exactly:

```text
echo-veil-agent --profile mercury doctor
```

Explain that full remember, recall, and forget operations are unavailable in
Mercury until Mercury provides a reviewed structured tool or MCP boundary. Do
not substitute Mercury's built-in memory and claim that Echo Veil handled it.
Do not describe the local AES-GCM staging adapter as a production enclave.
