# Coverage gate

CI uses cargo-llvm-cov on nightly for upstream Rust branch instrumentation.
Stable Rust remains the compiler for formatting, Clippy, native and wasm checks.
The gate requires exactly 100% covered production lines and branches, from the
LLVM JSON counts, and refuses absent or empty measurements. There are no
production-code exclusions. Test harness and fixture files are excluded because
they are validation inputs rather than shipped behavior. A failed gate is an
open test gap, never evidence of complete coverage.

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
