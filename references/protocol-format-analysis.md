# Protocol and File-Format Analysis

Use this reference for authorized protocol specimens, file formats, parsers, serializers, and stateful input processing.

## Inference workflow

1. Hash and preserve each specimen, capture, and output.
2. Normalize framing, encoding, compression, checksums, lengths, identifiers, and transport metadata without destroying the original.
3. Build controlled input/output pairs that change one field or state transition at a time.
4. Infer a grammar and state machine; mark each field as observed, inferred, or unknown.
5. Cross-check with source, disassembly, logs, a second implementation, or a round-trip/property test.
6. Test malformed lengths, nesting, encodings, truncation, duplicate fields, ordering, and state transitions only in a bounded local harness.

## Security review

Trace parser output to memory allocation, deserialization, authorization, filesystem, command, network, and update sinks. Check canonicalization, boundary arithmetic, recursion, decompression limits, error handling, and state reset. A parser accepting an unusual value is not a vulnerability without a security-relevant sink or impact.

Do not capture or replay third-party traffic without authorization. Defang sensitive endpoints and redact tokens, cookies, personal data, and proprietary payloads.
