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
  and native `LibsqlStore` through crlt. Evaluation itself never uses storage.

See [the implemented contract](docs/CONTRACT.md) for wire formats, trust inputs,
limits, and public/private boundaries. Complete signing and validation examples
are executable in [the shared test vectors](tests/shared.rs). Both platforms
verify the identical [v2 signed fixture](tests/vectors/admission.json) and
reject the [legacy signed fixture](tests/vectors/admission-v1.json), generated
with public deterministic fixture keys on GitHub Actions.

## Dependency survey

Surveyed crates.io metadata and upstream GitHub sources on 2026-09-30:

| Candidate | Decision and reason |
|---|---|
| [csgn](https://github.com/corbet-foss/csgn), [cshm](https://github.com/corbet-foss/cshm), [cpns](https://github.com/corbet-foss/cpns) | Use git revisions already on main: COSE Ed25519 verification, schema/profile validation and pin openings respectively. Disable csgn signing and cpns storage in the runtime dependency. No local replacement traits needed. |
| [crlt](https://github.com/corbet-foss/crlt) | Main already exposes community-scoped SQL, transactions and migrations. Use its git revision for the native adapter; no direct libsql fallback is necessary. It wraps official libsql 0.9.30. |
| [coset 0.4.2](https://github.com/google/coset) | Rechecked crates.io and upstream source for this alignment. csgn already wraps it with strict canonical framing and verification policy. Keep csgn as the runtime facade; use coset only in tests to prove alternate encodings preserve valid signatures. |
| [ed25519-dalek 3](https://github.com/dalek-cryptography/curve25519-dalek) | Strict verification of the authorized device's detached Ed25519 signature. csgn's COSE kinds cover issuer documents, not device presentations. No cryptographic primitive is implemented here. |
| [precis-profiles 0.2.0](https://github.com/sancane/precis) | Required maintained PRECIS UsernameCaseMapped implementation. |
| [unicode-security 0.1.2](https://github.com/unicode-rs/unicode-security) | Required UTS #39 skeleton and mixed-script implementation. Use the base script intersection for strict single-script handles. |
| [rustrict 0.7.39](https://github.com/finnbear/rustrict) | Maintained profanity detection with evasion handling. Enable only the stateless `censor` feature; no user context, clocks or customization. Predominantly English: not a guarantee of multilingual moderation. |
| [censor 0.3.0](https://github.com/kaikalii/censor) | Considered; older release and less comprehensive evasion handling than rustrict. |
| [cel-interpreter 0.10](https://github.com/cel-rust/cel-rust), [cedar-policy 4.13](https://github.com/cedar-policy/cedar) | Considered; general expression/authorization languages add semantics and capabilities this bounded, typed matching contract does not need. Keep a small conjunction dispatcher, delegate validation to cshm and exact numeric comparisons to BigDecimal. |
| [bigdecimal 0.4](https://github.com/akubera/bigdecimal-rs) | Exact decimal/scientific-notation comparisons, without platform-dependent binary floating point. Bound input length and exponent before comparison. |

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

GitHub Actions runs formatting, warning-free Clippy, native tests, the wasm
build check, and the **same** integration tests under Node's wasm runtime.
The metadata check requires first-party main declarations and rejects duplicate
resolved revisions throughout the graph. CI refreshes one coherent lock before
all substantive jobs; every job downloads and uses that exact snapshot.
No Cargo commands run on the workstation. CI retains its resolved lockfile;
no credentials are supplied to public CI.

Enable the default `storage` feature for crlt/libSQL on native targets. Use
`default-features = false` for just the portable core and memory cache. The
service appends `storage::SCHEMA` to its ordered crlt migrations and constructs
`LibsqlStore::new(&db, community)`. Use one database per community; the composite
community key also protects isolation when testing a shared database. The
adapter checks all query plans and atomically refuses revision/epoch rollback.

Real local libSQL tests cover persistence, idempotence, rollback conflicts,
namespace isolation, migration replay and indexed plans. The optional live
Turso test runs only when **both** `TURSO_URL` and `TURSO_TOKEN` are nonempty.
Use a disposable test database: it applies this crate's migration and writes
signed public fixtures. Credentials never belong in source control or CI.

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
Dependabot covers Cargo and GitHub Actions (there is no npm manifest here).
The merge workflow uses GitHub metadata only and requires every substantive CI
job and all published checks to succeed on the exact Dependabot head. It never
executes PR code with write permissions or bypasses branch protection.

[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) supplies LLVM line and
branch measurements; the strict gate and exclusions are in [COVERAGE.md](docs/COVERAGE.md).

The complete-publication adapter reuses portable `crbk` for rich policy semantics.
It authenticates the original separate revocations and uses the existing device,
profile and pin verifier. There is no second Rulebook implementation or unsigned
settings translation. Global and proof-time evidence absent from current cplc
credentials remains unavailable and fails closed when required.

Storage fault tests use the maintained upstream libsql engine to inject damaged
on-disk rows and ignored writes in temporary databases. Production storage stays
behind crlt's table/index-only migration and scoped-query boundary.
