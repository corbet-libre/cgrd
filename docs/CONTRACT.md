# cgrd contract, wire version 1 with cpns v2 pins

cgrd is the LGPL guard leaf of cvld's community gatekeeping facade. Its
stateless evaluator also runs on senders, forum services and recipients. It
checks person and profile together, evaluates reciprocal personal rules, and
provides handle-checking glue. It implements no cryptographic primitives,
reads no clock or network, records no login dates, requests, or raw gate data.

## Admission

`check(&Bundle, &Policy, schema_cose) -> Admission` returns `Admitted` with the
validated member/community/schema/scope, or `Refused` with stable reasons.
Checks stop at the first failing security stage. Profile failures include all
cshm violations. Reasons never contain answers, salts, signature bytes or raw
gate evidence. Success means the explicitly reported scope only.

The verifier supplies expected community, an authenticated csgn `KeyRing`,
Unix seconds, minimum epoch, minimum settings/schema snapshot revisions,
maximum snapshot age and signed settings. None comes from the peer. The ring's
issuer must equal the community. csgn authenticates protected kind, issuer,
key ID, issued time and exclusive expiry. Its authenticated key ring must use
csgn ring format v2, including the maximum accepted message lifetime; this
limit applies to credentials and both snapshot kinds. Alternate outer COSE
encodings are rejected even when the original signature remains valid.
Protected CWT claims and document kind must be marked critical by csgn.
Both snapshots must be unexpired,
within the maximum age, above revision floors and share an acceptable epoch.
A caller that forgets its floors loses rollback protection; storage alone
cannot establish current revocation state.

Settings and schema COSE payloads are JSON `Snapshot<T>` objects:
`community`, positive `revision`, `policy_epoch`, `content`. Their protected
kinds are `SettingsSnapshot` and `SchemaSnapshot`. Content is `Settings` and
`cshm::Schema` respectively. Settings contain required gates with explicit
provider allowlists, current revoked members/device keys, and reserved handles.
All required gates are conjunctive; resolution of richer community policy
belongs upstream to crbk. Revocations here are part of the signed settings,
so a separately supplied revocation document cannot be silently ignored.

The `Credential` JSON payload uses csgn kind `Credential`:
`community`, `member` (community pseudonym), canonical `handle`,
`schema_version`, `policy_epoch`, `gates`, `pins`, and `devices` (Ed25519 public
keys). Each gate contains only gate/provider/exclusive expiry; its level is
community and subject is the enclosing member. Each pin has schema field ID
and a 32-byte cpns **v2** fingerprint. Issued time, expiry and signing key ID live
once in csgn's authenticated envelope. Every gate expiry must cover the entire
credential lifetime. Duplicate gates, pin IDs and device keys are refused.
Credential epoch and schema version must exactly match the snapshots.

`BundleContent` JSON has `community`, `member`, `device` (32 bytes),
`credential` (COSE bytes), tagged `profile`, and `openings`. `Bundle` contains
those **exact** UTF-8 bytes as `payload` plus a 64-byte detached signature.
The device signs `b"cgrd:bundle:v1\0" || payload` using ordinary Ed25519.
`binding_bytes` constructs this message. Verification uses dalek's strict
verifier. Community/member must match the credential; the signing device must
be authorized in that credential and absent from current revocations. Every
payload byte is bound, including the credential, scope, profile and salts.
JSON member order/whitespace need not be canonical: verify original bytes,
never reserialize them before signature verification. Typed envelopes reject
unknown/duplicate fields. This is a reusable presentation, not a session nonce.

Profiles are `{"scope":"public","profile":<cshm::PublicProfile>}` or
`{"scope":"full","profile":<cshm::Profile>}`. cshm validates types, required
fields, community/version, choices, bounds and contact-check requirements.
The forum receives only a public presentation. Full presentations are for
local devices/authorized recipients. The member must sign each projection
separately; discarding private fields invalidates an existing signature.

Every presented stable/occasional field requires a signed pin and opening.
Optional absent fields need neither; a presented field cannot omit its pin,
and an existing pin cannot be hidden by dropping its field. Openings contain
only `field` and `salt`; the value is always read from the validated profile.
The complete profile also checks private pins; public presentations leave
private pins unopened and reject private openings. Undeclared/free-field pins,
extra/duplicate openings and salts outside 16..=1024 bytes are refused.
Pin encoding is `pin_value_bytes`: compact JSON with recursively sorted object
keys, UTF-8 text, and retained number spellings. Thus `34` and `34.0` compare
equally for matching but are deliberately distinct pin encodings. cpns owns
the domain-separated fingerprint construction and constant-time opening check.
Use `cpns::fingerprint_v2` / `cpns::check_opening_v2` with
`FingerprintContext { community, member, field }`: the exact UTF-8 community
and member from the authenticated credential and the validated schema field ID.
There is no normalization, inferred digest version, or v1 fallback. A v1 pin
or a v2 pin copied from another community, member or field is refused even
inside a newly signed credential and correctly device-signed bundle.
The JSON value encoding and bundle signing domain stay v1; the pin algorithm
is fixed to v2 by this contract. Existing v1 pins require newly issued
credentials with v2 pins, and old key rings must be republished in csgn v2
format. Devices must retain their field values and salts to reseal them.
Older COSE envelopes lacking critical headers must also be reissued.
Salt generation/freshness and zeroization of caller buffers belong to devices.

Without a deterministic contact detector, fields marked `no_contact_details`
fail closed. `check_with_contact` delegates to cshm's detector callback. The
same callback implementation must be used across platforms.

## Matching

`Participant::new(member, public_profile, schema, rules)` validates the schema,
public answers and rules before allowing `matches(a, b)`. It does not
authenticate identity; construct it from data already admitted by the guard.
Only **public and filterable** fields enter its attribute map. Both peers must
have exactly the same schema definition/community/version and different
member IDs. Invalid rules never become vacuously successful.

Rules form a bounded conjunction: typed `equal`, inclusive `number_range`,
choice `one_of`, WGS84 `distance_range`, and `block` by member pseudonym. Equality covers boolean,
number, choice, text and exact location coordinates. Text/choice equality is
case-sensitive. Numeric equality and ranges use BigDecimal, including
scientific notation, never f64. Numeric text uses the shared cshm parser: at most 128 bytes, explicit exponent
and resulting scale in -128..=128, checked before exact arithmetic. Both profile
validation and matching can reject extremely large
numbers that cshm accepts. No scripting is accepted.

`distance_range` has `field`, `min_meters` and `max_meters`. It compares the
WGS84 ellipsoidal geodesic between the owner's and candidate's value of the same
public, filterable location field. Both bounds are inclusive nonnegative decimal
strings using the same size/exponent limits; inverted bounds refuse construction.
The owner must provide that location to construct the rule; a missing candidate
location fails the match. Each participant's bounds apply independently.
GeographicLib supplies the inverse calculation, including poles, antimeridian and
antipodal cases. Coordinates retain their original exact decimal representation;
only the derived geodesic uses the maintained library's f64 precision. No grid,
coarsening, altitude, route length or ranking is introduced. Nonfinite output
refuses the comparison. Existing exact location equality is unchanged.
Missing optional values fail an applicable rule. A block in either direction
prevents a match. A's failures precede B's, each in source rule order.

`MatchFailure` identifies the owner, rule index, declared field and reason.
The owner combines this with its own rules to render the full explanation.
Only `requester_fields()` is suitable for disclosure to the other party: sorted,
deduplicated field names, never values, bounds or rule indices. Blocks and
pair-level failures have no field and need a generic refusal.

## Handles

`check_handle(handle, reserved)` applies precisely pinned PRECIS
UsernameCaseMapped, counts normalized Unicode scalar values (8..=32), checks
UTS #39 mixed-script and the base script intersection, checks rustrict's
stateless inappropriate-content verdict, and compares reserved skeletons.
Common/Inherited characters are neutral; Japanese/Korean multiscript
augmentations are excluded by the strict base-script rule. A purely neutral
PRECIS identifier (such as digits) is permitted. Reserved entries need not
meet the length rule but must pass PRECIS; invalid entries fail closed.

Success returns `normalized` and the UTS #39 `skeleton`. The register must
atomically reserve that skeleton per community. cgrd does not query uniqueness.
Normalization is allowed at handle selection; credentials must already contain
the normalized spelling. Unicode/profanity updates can change verdicts and
must be coordinated across native/wasm consumers. Profanity coverage is mainly
English; no claim of perfect or universal moderation is made.

## Storage and limits

`Store` has `load(kind)` and atomic `save(verified_record)`; implementations
are `MemoryStore` and native `LibsqlStore` using the ready crlt git API. Only
signature-checked settings and schemas can construct a `SnapshotRecord`.
Loaded bytes are untrusted until verified again. No bundles, profiles,
credentials, pin openings or activity history are stored.

Deploy one DB per community. The table `cgrd_snapshots` contains
`community_id`, `kind`, `revision`, `policy_epoch`, `cose`; primary key
`(community_id, kind)` WITHOUT ROWID. crlt injects scope in every SQL statement.
Save rejects cross-community records, decreasing epochs, decreasing revisions,
and different bytes at an equal revision. Exact replay is idempotent.
Persisted revisions and epochs must fit nonnegative signed 64-bit integers.
SELECT/INSERT/UPDATE plans are verified with EXPLAIN QUERY PLAN. The caller
owns migrations and database credentials. A remote failure may leave write
outcome uncertain; reconcile through load, then reverify.

Bundle/snapshot bytes are capped at 1 MiB. Collections of fields, gates,
devices, openings, rules, reserved handles and current revocations are capped
at 256; identifiers at 256 bytes, individual handle inputs at 4096 bytes.
Callers must cap transport allocation before deserializing an outer Bundle.
Current revocation capacity and latest-only snapshot caching are deliberate
v1 limits: larger communities and retained historical schemas need upstream
composition or a future contract revision.

## Acceptance and remaining integration work

CI runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, `cargo check --target wasm32-unknown-unknown`, and executes the
same shared admission/matching/Unicode vectors on native and wasm. Tests use
real csgn signatures, real cpns v2 fingerprints, cshm validation, and local libSQL
round trips, including isolation and indexed plans. No mocks of our logic.
Live Turso tests skip unless both environment credentials are nonempty.
Shared regressions reject a frozen legacy v1 presentation, fingerprints with
any wrong context component, non-canonical COSE at all three admission
boundaries and snapshot-cache verification, and messages exceeding the
authenticated ring's lifetime limit.
The accepted frozen fixture contains cpns v2 pins and a csgn v2 key ring;
native and wasm must verify identical bytes and reproduce them deterministically.
First-party dependencies follow main. CI resolves one lock snapshot shared by all
jobs and rejects inconsistent first-party revisions across the graph.

The community issuer must adopt this credential/device-authorization wire
format. Trust-root distribution, fresh revocation delivery, persisted floor
selection, challenges against replay, handle reservation, and application
contact detection are caller responsibilities. Pin and signature primitives
remain in established crates. Never publish this crate to a registry.

## Complete cplc publication adapter

`check_published` accepts `PublishedPolicy`: trusted authority/time/floors, the
original settings, schema and separate revocation COSE bytes, and the trusted
action name. Every document is authenticated independently with csgn; all epochs
must agree. Separate member and device revocations are mandatory and checked
before device binding. The legacy `Settings` format remains supported only by
`check`; no translation into that format is performed.

The complete signed flat policy is passed to `crbk::Snapshot::may`, retaining
all/any/threshold groups, switches, providers, membership and proof-age semantics.
The original credential authenticates only community gate metadata and admitted
membership, as attested by cplc issuance. No global proof or proof time is
inferred. A policy requiring unavailable evidence refuses through Rulebook.
The same credential, device signature, cshm profile and cpns pin checks serve both
public adapters. Handle reservation remains an issuer/membership responsibility.
