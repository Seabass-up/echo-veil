# Retrieval quality

Echo Veil's release gate measures retrieval behavior instead of treating an
installed embedding model as proof of quality.

## Current local result

On 2026-07-21, `qwen3-embedding:latest` at 1,024 dimensions passed the committed
neutral suite with:

- 42/42 correct top-1 results: 17 keyword, 19 paraphrase, 2 current-update,
  2 temporal, and 2 long-memory queries;
- 14/14 unrelated and same-subject/absent-fact queries rejected;
- 17/17 keyword records recovered and 14/14 distractors rejected through the
  read-only always-available layer with semantic embeddings unavailable;
- 202.14 ms mean and 221.26 ms p95 recall;
- 2,974.80 ms for the cold first protected remember, including local model
  startup;
- 150.01 ms mean remember after that first operation; and
- 2.43 ms to reopen and restore the persisted profile.

The same committed corpus, queried through the installed OpenClaw memory-core
CLI, returned 32/42 correct top-1 results and rejected 9/14 distractors. Its
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
- a second predicate-focused answerability embedding that masks grammatical
  subjects and rejects subject-only matches at a separately calibrated `0.42`;
- AES-GCM-protected passage vectors and MaxSim for long memories;
- bounded candidate generation from live memory, persisted LSH, and lexical hits;
- keyed-hash lexical features, so searchable terms are not stored in plaintext;
- topic-aware maximal marginal relevance for result diversity;
- explicit `effective_at` and `supersedes` links for current and point-in-time
  truth; and
- fail-closed embedding identity binding to model digest, dimension, and query
  instruction.

Broad retrieval and answerability queries are batched into one Ollama request.
The broad candidate threshold is `0.44`; candidates that pass it still must pass
the answerability gate. The committed hard negatives include unknown passport,
medication-allergy, shoe-size, and sports-team attributes for a person who does
have other stored records.

An additional 24-record host-profile pilot retained 8/8 keyword top-1 results,
improved exact-label paraphrase recall from 10/14 to 12/14, and improved
unrelated rejection from 6/10 to 10/10. The two remaining exact-label misses
returned relevant but broader or adjacent records at rank one, while both
intended records ranked second for 14/14 top-2 coverage. They remain visible as
ranking ambiguity rather than being hidden by corpus-specific rules.
Fresh-process RPC time averaged 335 ms with a 339 ms p95 on that run, down from
the pre-fix pilot's 1.89-second mean despite the added second-stage check.

The source payload, protected vectors, and keyed lexical index persist across a
restart. If Ollama or the configured model is unavailable, an existing profile
can provide explicitly degraded, read-only keyed recall without hashing or
lifecycle mutation. Model-identity changes, malformed responses, invalid keys,
and corrupt storage still fail closed.

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
