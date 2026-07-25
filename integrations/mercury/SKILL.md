---
name: echo-veil
description: Verify Echo Veil readiness in Mercury without leaking protected memory through the shell.
version: 0.7.0
category: developer-tools
intents:
  - echo veil memory
  - check echo veil
  - verify protected memory
tags:
  - memory
  - privacy
  - echo-veil
allowed-tools:
  - run_command
---

# Echo Veil for Mercury

Mercury's Agent Skills contract can temporarily elevate the built-in
`run_command` tool, but its documented extension surface does not provide
arbitrary MCP or structured custom-tool registration. A shell command string is
not a safe payload transport. This skill therefore exposes only a safe
readiness check. It must not send memory topics, payloads, queries, identifiers,
keys, or other user content through `run_command`, command arguments, shell
pipelines, temporary files, URLs, logs, or environment variables.

## Exclusive-authority status

Do not enable or claim Echo Veil singular-memory authority in Mercury. The
reviewed Mercury runtime constructs its native Short-Term, Long-Term, and
Episodic memory stores even when its optional Second Brain is disabled.
`SECOND_BRAIN_ENABLED=false` is not an all-memory-off switch: Mercury then
falls back to basic Long-Term fact search. Its native JSON, JSONL, and SQLite
paths therefore remain a competing mutable memory authority.

Do not use Mercury's `save_memory`, `search_memory`, `/memory`, automatic fact
extraction, consolidation, or native memory stores as substitutes for Echo
Veil. Installing this skill must not mutate Mercury's memory configuration.
Full support requires a reviewed upstream backend or structured hook that
routes pre-model doctor, minimal recall, Contextual Logic, authorized writes,
refresh, promotion, and forgetting through Echo Veil while suppressing every
native mutable memory path. It must also abort a model turn when the required
preflight fails. Until that boundary exists and is exercised in the real host,
Mercury is incompatible with singular-authority mode.

## Readiness-only operation

When the user asks to check Echo Veil, run exactly:

```text
echo-veil-agent --profile echo-universal-qwen3-v1 --scope local-user --caller mercury --embedder ollama --embedding-model qwen3-embedding:latest --embedding-dimension 1024 doctor
```

Explain that full remember, recall, and forget operations are unavailable in
Mercury until Mercury provides a reviewed structured tool or MCP boundary. Do
not substitute Mercury's built-in memory and claim that Echo Veil handled it.
Do not describe the local AES-GCM staging adapter as a production enclave.

Install this reviewed local skill with:

```text
mercury skills install --from ./integrations/mercury/SKILL.md
mercury skills list
```

Installing the skill does not execute it and does not make Mercury's native
Second Brain protected by Echo Veil.
