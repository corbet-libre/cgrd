# Coverage gate

CI uses cargo-llvm-cov on nightly for upstream Rust branch instrumentation.
Stable Rust remains the compiler for formatting, Clippy, native and wasm checks.
The gate requires exactly 100% of LLVM LCOV's emitted production source lines
and branch records, refusing absent data, duplicate records and zero or unknown
branch counters. JSON summaries and annotated instantiations remain artifacts.
This measures source coverage, not every generic instantiation. LLVM's JSON
summary can report unexecuted generic copies despite positive merged source
counters; run36899964639 contains both reports from the same execution.

One line-only exclusion is recorded in `coverage-exclusions.json`: the defensive
serialization-error conversion for the concrete profile/schema/rule tuple.
These derived serializers have string map keys and valid JSON values; they cannot
return a serialization error. Size-limit, profile and rule validation still run
and are measured. The gate verifies the exact source line and rejects any branch
at that location. Input representation changes require reassessing this exception.
No SQL, signature, policy, device or other refusal path is excluded. Test harness
and fixture files are omitted because they are validation inputs, not shipped
behavior. A failed gate is an open gap, never complete-coverage evidence.

Dependencies are resolved once per CI run and the resulting Cargo.lock artifact
is reused by every job. CI refreshes within the declared ranges;
Dependabot proposes lockfile updates for review and merging after full CI.
The checked-in lock and per-run artifacts retain exact reproducible resolutions.

The bundle parser limits the complete serialized JSON before decoding. A nested
credential's numeric byte array cannot be longer than that enclosing JSON, so
the redundant post-decode byte count was removed. Oversized outer bundles and
independent snapshot limits remain enforced and tested; no exclusion is used.

The common credential verifier requires every proof expiry to cover the signed
credential lifetime, and csgn requires that lifetime to include the supplied
clock. The legacy required-gate loop therefore no longer repeats the implied
proof-expiry comparison. The mandatory common lifetime check remains tested.

Input size and snapshot scope checks use shared non-generic helpers. Every
snapshot payload type passes the same checks before typed use; contact detection
also uses one borrowed callback body. This avoids duplicate generic validation
bodies in instrumentation without changing refusals. CI retains LLVM's annotated
text with instantiations from the same test execution for remaining-gap review.
