# Retrieval quality

Echo Veil's release gate measures retrieval behavior instead of treating an
installed embedding model as proof of quality.

## Current local result

On 2026-07-21, `qwen3-embedding:latest` at 1,024 dimensions passed the committed
neutral suite with:

- 42/42 correct top-1 results: 17 keyword, 19 paraphrase, 2 current-update,
  2 temporal, and 2 long-memory queries;
- 10/10 unrelated queries rejected;
- 123.62 ms mean and 140.11 ms p95 recall;
- 1.22 seconds for the first protected remember with the model fully unloaded;
- 130.25 ms mean remember after that cold start; and
- 2.59 ms to reopen and restore the persisted profile.

The same committed corpus, queried through the installed OpenClaw memory-core
CLI, returned 32/42 correct top-1 results and rejected 9/10 distractors. Its
category result was 17/17 keyword, 10/19 paraphrase, 2/2 current-update, 1/2
temporal, and 2/2 long-memory. The CLI-level latency measurement includes host
process overhead and therefore is not used as a direct engine-latency claim.

This is a meaningful same-machine, same-corpus pilot result. It is not evidence
that Echo Veil is universally better than every memory product. The corpus is
small and synthetic, and the comparison covers retrieval rather than complete
capture, generation, cost, or multi-tenant operations.

## What the gate covers

The adapter combines:

- instruction-aware local Qwen3 query embeddings;
- AES-GCM-protected passage vectors and MaxSim for long memories;
- bounded candidate generation from live memory, persisted LSH, and lexical hits;
- keyed-hash lexical features, so searchable terms are not stored in plaintext;
- topic-aware maximal marginal relevance for result diversity;
- explicit `effective_at` and `supersedes` links for current and point-in-time
  truth; and
- fail-closed embedding identity binding to model digest, dimension, and query
  instruction.

The source payload, protected vectors, and keyed lexical index persist across a
restart. If Ollama is unavailable or the resolved model digest changes, startup
fails explicitly; it never falls back to hashing.

The hashing migration rehydrates content and explicit supersession history into
new vine IDs. It intentionally does not copy lifecycle scores, reinforcement
age, locks, or archive position from the source profile.

## Reproduce

```bash
ollama pull qwen3-embedding:latest
ollama stop qwen3-embedding:latest
uv run --locked python scripts/quality_benchmark.py
uv run --locked python scripts/memory_core_benchmark.py
```

The OpenClaw comparison creates an isolated temporary agent, indexes the same
records, runs the cases, and removes the agent in a `finally` block.

## The next evidence bar

Before making broad comparative claims, run independent standardized suites
such as [LongMemEval](https://arxiv.org/abs/2410.10813) and LoCoMo, publish the
exact model/hardware/configuration, and report retrieval and end-to-end answer
quality separately. Real deployment qualification should add the authorized
application corpus, multilingual queries, adversarial near-misses, larger
corpora, concurrent writers, and long-duration lifecycle behavior.
