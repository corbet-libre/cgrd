# cgrd

Stateless admission, reciprocal profile matching and handle checks for `cvld`.
Native Rust and `wasm32-unknown-unknown` share the same evaluation code. The
interface is experimental and is not published to a registry.

- `check_published` verifies the full signed Rulebook policy and separate revocations.
- `check(bundle, policy, schema)` verifies legacy signed settings, a COSE community
  credential, the authorized device's signature, cshm validation and cpns pins.
- `Participant::new(...)` validates public attributes and compiles personal
  rules; `matches(a, b)` checks both directions with structured reasons.
- `check_handle(handle, reserved)` returns PRECIS-normalized text and its
  confusable skeleton, or stable refusal reasons.
- `storage::Store` offers a community-bound snapshot cache with `MemoryStore`
  and an explicit caller-owned persistence port. Evaluation never uses storage.

See [the implemented contract](docs/CONTRACT.md) for wire formats, trust inputs,
limits, and public/private boundaries. Complete signing and validation examples
are executable in [the shared test vectors](tests/it/shared.rs). Both platforms
verify the identical [v2 signed fixture](tests/vectors/admission.json) and
reject the [legacy signed fixture](tests/vectors/admission-v1.json), generated
with public deterministic fixture keys in CI.

## Scope

Guard validates person and profile together, evaluates reciprocal public rules,
and checks handles. It owns no member registry, private-profile search, ranking
or network I/O. Signed issuer policy stays with Rulebook and csgn; geographic
rules delegate WGS84 geodesics to GeographicLib. Time and trust material are
caller-supplied, and missing authority or profile evidence fails closed.

## Dependency survey

Surveyed crates.io metadata and upstream sources on 2026-09-30:

| Candidate | Decision and reason |
|---|---|
| [csgn](https://github.com/corbet-foss/csgn), [cshm](https://github.com/corbet-foss/cshm), [cpns](https://github.com/corbet-foss/cpns) | Use git revisions already on main: COSE Ed25519 verification, schema/profile validation and pin openings respectively. Disable csgn signing and cpns storage in the runtime dependency. No local replacement traits needed. |
| [crlt](https://git.corbet.ch/corbet-foss/crlt) | Development-only host integration example, exercising real SQL transactions. No database implementation or connection is part of this library. |
| [coset 0.4.2](https://github.com/google/coset) | Rechecked crates.io and upstream source for this alignment. csgn already wraps it with strict canonical framing and verification policy. Keep csgn as the runtime facade; use coset only in tests to prove alternate encodings preserve valid signatures. |
| [ed25519-dalek 3](https://github.com/dalek-cryptography/curve25519-dalek) | Strict verification of the authorized device's detached Ed25519 signature. csgn's COSE kinds cover issuer documents, not device presentations. No cryptographic primitive is implemented here. |
| [precis-profiles 0.2.0](https://github.com/sancane/precis) | Required maintained PRECIS UsernameCaseMapped implementation. |
| [unicode-security 0.1.2](https://github.com/unicode-rs/unicode-security) | Required UTS #39 skeleton and mixed-script implementation. Use the base script intersection for strict single-script handles. |
| [rustrict 0.7.39](https://github.com/finnbear/rustrict) | Maintained profanity detection with evasion handling. Enable only the stateless `censor` feature; no user context, clocks or customization. Predominantly English: not a guarantee of multilingual moderation. |
| [censor 0.3.0](https://github.com/kaikalii/censor) | Considered; older release and less comprehensive evasion handling than rustrict. |
| [cel-interpreter 0.10](https://github.com/cel-rust/cel-rust), [cedar-policy 4.13](https://github.com/cedar-policy/cedar) | Considered; general expression/authorization languages add semantics and capabilities this bounded, typed matching contract does not need. Keep a small conjunction dispatcher, delegate validation to cshm and exact numeric comparisons to BigDecimal. |
| [bigdecimal 0.4](https://github.com/akubera/bigdecimal-rs) | Exact decimal/scientific-notation comparisons, without platform-dependent binary floating point. Bound input length and exponent before comparison. |

The distance extension was surveyed on 2026-10-01. Use
[geographiclib-rs](https://docs.rs/geographiclib-rs/latest/geographiclib_rs/) with
compatible `0.2` updates and polygon-only accuracy features disabled: it provides
the maintained Rust WGS84 inverse calculation and upstream boundary vectors.
[GeoRust geo](https://github.com/georust/geo) wraps the same engine with additional
geometry APIs this rule does not need. The C-backed `geographiclib` crate adds an
unneeded foreign runtime for the shared wasm target. No geodesic primitive is
implemented here. Exact numeric/location equality continues to use BigDecimal;
derived distance has the upstream floating-point precision documented in CONTRACT.

First-party dependencies follow main and resolve to one full revision per crate
in the shared CI lock snapshot. Portable crbk supplies the complete admission
policy evaluator; csgn authenticates issuer documents, cshm validates profiles,
and cpns verifies bound pins. No cpsd or FSL dependency enters this leaf.

Serde/serde_json and thiserror provide wire decoding and typed errors. Tokio,
tempfile, upstream libsql and wasm-bindgen-test support real integration tests.
Unicode/profanity dependencies use compatible version ranges; the committed and
CI-resolved lock snapshots keep each tested dependency graph reproducible.
Consumers must coordinate verdict-affecting updates across native and wasm.

## Validation and storage

CI runs formatting, warning-free Clippy, native tests, the wasm
build check, and the **same** integration tests under Node's wasm runtime.
The metadata check requires first-party main declarations and rejects duplicate
resolved revisions throughout the graph. CI refreshes one coherent lock before
all substantive jobs; every job downloads and uses that exact snapshot.
CI retains its resolved lockfile;
no credentials are supplied to public CI.

The library is RAM-only. `MemoryStore` is a process-local reference cache;
`storage::Store` is the caller-owned atomic persistence port. The retained empty
`storage` feature is a compatibility flag and opens no database. Database URLs,
credentials, migrations, connections and durable transaction implementations
belong to the application. The test-only `tests/support/snapshot_sql.rs` example
shows a host implementation and retains real local SQL integration checks.

A host saves only signature-verified settings/schema snapshots. Use the immutable
`SnapshotRecord::{community,kind,stored}` accessors and run `check_replacement`
inside the same atomic transaction as the write. Load results remain untrusted
until signature validation; persisted floors alone never establish authority.

All profile, rule, pin and handle evaluation is local. Callers can preview their
actual rules using these same pure functions and explicit dummy inputs; that does
not mint a credential or establish a real person's attributes. There is no billed
provider dispatch, quote acquisition or fallback, and no provider credentials.
Host compute, storage and any external verification service have separate costs;
this library does not label them free. Raw profiles, credentials and openings
remain transient and are never submitted to the snapshot port. Host memory
management controls swap/dumps; upstream parsers may make temporary RAM copies.

Real local SQL tests cover host persistence, idempotence, rollback conflicts,
namespace isolation, migration replay and indexed plans. The opt-in live Turso
probe is ignored by default, requires explicit test selection plus both
`TURSO_URL` and `TURSO_TOKEN`, uses a disposable database and is not run as part
of this implementation. Supplying credentials is not permission
to run a potentially billable probe.

## Integration limits

Credentials must now carry cpns v2 pins created with `FingerprintContext` from
the credential community/member and schema field ID. Legacy unbound pins are
refused; devices must reseal and obtain new credentials. Trust distributors
must also publish csgn v2 key rings, which authenticate the lifetime limit.
Reissue older snapshots and credentials without csgn's required critical headers.
The bundle JSON layout, signing domain and `check` API remain unchanged.

The service must authenticate key rings, distribute fresh snapshots, retain
revision/epoch floors, and choose the explicit clock. Stateless verification
cannot discover a withheld revocation or prevent replay of an otherwise valid
presentation. Callers implement session challenges if they need freshness of
possession. Device authorization is certified in the community credential;
issuance and revocation publication belong to the community service.

For text fields marked `no_contact_details`, supply a deterministic detector
through `check_with_contact` / `Participant::with_contact`; the default fails
closed. Requesters receive only `MatchResult::requester_fields()`, never the
owner-facing rule indices. Handle uniqueness is an atomic reservation of the
returned skeleton by the register, outside this crate.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under [LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt) [WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt). See [LICENSE.md](LICENSE.md).

## Dependency maintenance and coverage

First-party dependencies follow `main`; Cargo.lock records one exact revision
per crate. CI checks the entire resolved graph, including optional declarations.
Dependency updates must pass every substantive CI job and published check on
the exact candidate revision before merging. Update automation must never
execute candidate code with write permissions or bypass branch protection.

[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) supplies LLVM line and
branch measurements; the strict gate and exclusions are in [COVERAGE.md](docs/COVERAGE.md).

The complete-publication adapter reuses portable `crbk` for rich policy semantics.
It authenticates the original separate revocations and uses the existing device,
profile and pin verifier. There is no second Rulebook implementation or unsigned
settings translation. Global and proof-time evidence absent from current cplc
credentials remains unavailable and fails closed when required.

Storage fault tests use the maintained upstream libsql engine to inject damaged
on-disk rows and ignored writes in temporary databases. Application storage stays
behind crlt's table/index-only migration and scoped-query boundary.
