# Concurrency, Side Channels, and Data-Flow Analysis

Use this reference for race conditions, TOCTOU, timing/cache/error channels, secret flow, privacy leakage, and asynchronous consistency hypotheses.

## Analysis model

For concurrency:

```text
shared state → check → interleaving or stale view → use/sink → protected impact
```

For data flow:

```text
source → transformation/validation → storage/log/transport → sink → audience or impact
```

Identify the principal, synchronization primitive, transaction or cache boundary, and final protected asset. Trace synchronous and asynchronous paths separately.

## Safe validation

Use a local fixture with synthetic records and bounded repetitions. Prefer deterministic barriers, controlled scheduling, fake clocks, or instrumented test hooks to high-rate load. For timing claims, collect repeated paired samples, control environmental noise, and report uncertainty; never infer a secret from one noisy measurement. For privacy claims, prove the data reached an unauthorized audience or durable sink, not merely that it existed in memory.

Check transactions, idempotency, replay keys, lock scope, cache invalidation, queue retries, audit ordering, redaction, structured logs, metrics, traces, and error responses.

## Evidence boundary

A race requires a repeatable interleaving and security impact. A timing difference requires a stable distinguishable signal and a practical observation model. A source-to-sink path requires an actual exposure or policy failure. Otherwise classify the result as an unresolved hypothesis or hardening recommendation.
