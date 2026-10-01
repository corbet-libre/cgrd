use std::collections::BTreeSet;

use csgn::{KeyRing, Kind};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::*;

/// Trust inputs owned by the verifier, never taken from the submitted bundle.
pub struct Policy<'a> {
    /// Expected community, also the trusted csgn issuer.
    pub community: &'a str,
    /// Authenticated issuer keys, distributed out of band.
    pub keys: &'a KeyRing,
    /// Current Unix seconds, explicit for deterministic native/wasm execution.
    pub now: u64,
    /// Lowest acceptable admission epoch learned by the caller.
    pub minimum_epoch: u64,
    /// Lowest settings revision learned by the caller.
    pub minimum_settings_revision: u64,
    /// Lowest schema snapshot revision learned by the caller.
    pub minimum_schema_revision: u64,
    /// Maximum snapshot age in seconds, in addition to signed expiry.
    pub maximum_snapshot_age: u64,
    /// Signed csgn settings snapshot containing [`Snapshot<Settings>`].
    pub settings: &'a [u8],
}

/// Complete cplc publications, kept as their original signed bytes.
/// Construct from a current authenticated Charter or equivalent trusted floors.
pub struct PublishedPolicy<'a> {
    /// Shared authority, clock, settings bytes and revision floors.
    pub policy: Policy<'a>,
    /// Original separate `RevocationListSnapshot` bytes.
    pub revocations: &'a [u8],
    /// Lowest authenticated revocation publication revision.
    pub minimum_revocations_revision: u64,
    /// Rulebook action selected by trusted application configuration.
    pub action: &'a str,
}

/// Verify a presentation using the complete flat Rulebook policy and separate
/// revocations. Missing global proofs or proof times fail closed in Rulebook.
pub fn check_published(bundle: &Bundle, policy: &PublishedPolicy<'_>, schema: &[u8]) -> Admission {
    check_published_with_contact(bundle, policy, schema, &|_| cshm::ContactCheck::Unavailable)
}

/// As [`check_published`], with a deterministic contact detector.
pub fn check_published_with_contact(
    bundle: &Bundle,
    policy: &PublishedPolicy<'_>,
    schema: &[u8],
    contact: &dyn Fn(&str) -> cshm::ContactCheck,
) -> Admission {
    match evaluate_published(bundle, policy, schema, contact) {
        Ok(admission) => admission,
        Err(reason) => Admission::Refused {
            reasons: vec![reason],
        },
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocations {
    members: BTreeSet<String>,
    devices: BTreeSet<[u8; 32]>,
}

struct VerifiedRules {
    epoch: u64,
    schema: cshm::Schema,
    revocations: Revocations,
    reserved_handles: Vec<String>,
    gates: GatePolicy,
}

enum GatePolicy {
    Legacy(Vec<GateRequirement>),
    Published {
        snapshot: crbk::Snapshot,
        action: String,
    },
}

impl GatePolicy {
    fn check(&self, credential: &Credential, now: u64) -> Result<(), Refusal> {
        let allowed = match self {
            Self::Legacy(required) => required.iter().all(|required| {
                credential
                    .gates
                    .iter()
                    .any(|g| g.gate == required.gate && required.providers.contains(&g.provider))
            }),
            Self::Published { snapshot, action } => {
                let gates = credential
                    .gates
                    .iter()
                    .map(|gate| {
                        Ok(crbk::GateResult {
                            gate: gate.gate.clone(),
                            level: crbk::GateLevel::Community,
                            subject: credential.member.clone(),
                            community: Some(credential.community.clone()),
                            provider: gate.provider.clone(),
                            valid_until: i64::try_from(gate.valid_until)
                                .map_err(|_| Refusal::Gate)?,
                            // cplc intentionally does not disclose this metadata.
                            proven_at: None,
                        })
                    })
                    .collect::<Result<Vec<_>, Refusal>>()?;
                snapshot
                    .may(
                        crbk::Subject {
                            id: &credential.member,
                            membership: crbk::MembershipState::Admitted,
                        },
                        action,
                        &gates,
                        i64::try_from(now).map_err(|_| Refusal::Gate)?,
                    )
                    .map_err(|_| Refusal::Gate)?
                    .allowed
            }
        };
        if allowed { Ok(()) } else { Err(Refusal::Gate) }
    }
}

fn evaluate_published(
    bundle: &Bundle,
    published: &PublishedPolicy<'_>,
    schema_bytes: &[u8],
    contact: &dyn Fn(&str) -> cshm::ContactCheck,
) -> Result<Admission, Refusal> {
    let policy = &published.policy;
    let (settings, settings_issued) = snapshot::<crbk::Values>(
        policy.settings,
        policy.community,
        policy.keys,
        Kind::SettingsSnapshot,
        policy.now,
    )?;
    let (schema, schema_issued) = snapshot::<cshm::Schema>(
        schema_bytes,
        policy.community,
        policy.keys,
        Kind::SchemaSnapshot,
        policy.now,
    )?;
    let (revocations, revocations_issued) = snapshot::<Revocations>(
        published.revocations,
        policy.community,
        policy.keys,
        Kind::RevocationListSnapshot,
        policy.now,
    )?;
    if settings.revision < policy.minimum_settings_revision
        || schema.revision < policy.minimum_schema_revision
        || revocations.revision < published.minimum_revocations_revision
        || settings.policy_epoch < policy.minimum_epoch
        || settings.policy_epoch != schema.policy_epoch
        || settings.policy_epoch != revocations.policy_epoch
        || schema.content.community != policy.community
    {
        return Err(Refusal::Snapshot);
    }
    if [settings_issued, schema_issued, revocations_issued]
        .iter()
        .any(|issued| policy.now.saturating_sub(*issued) > policy.maximum_snapshot_age)
    {
        return Err(Refusal::StaleSnapshot);
    }
    if revocations.content.members.len() > MAX_ITEMS
        || revocations.content.devices.len() > MAX_ITEMS
        || revocations
            .content
            .members
            .iter()
            .any(|member| !identifier(member))
        || schema.content.public.len() + schema.content.private.len() > MAX_ITEMS
    {
        return Err(Refusal::Metadata);
    }
    // This is the exact authenticated flat content, with the protected issuance
    // time restored for the upstream evaluator. No settings are synthesized.
    let snapshot = crbk::Snapshot {
        community: settings.community,
        kind: crbk::SnapshotKind::Settings,
        revision: settings.revision,
        policy_epoch: settings.policy_epoch,
        issued: i64::try_from(settings_issued).map_err(|_| Refusal::Snapshot)?,
        content: settings.content,
    };
    // Reserved handles are membership-owned. No unsigned override is accepted;
    // the credential attests reservation, while Guard checks canonical spelling.
    let rules = VerifiedRules {
        epoch: settings.policy_epoch,
        schema: schema.content,
        revocations: revocations.content,
        reserved_handles: vec![],
        gates: GatePolicy::Published {
            snapshot,
            action: published.action.into(),
        },
    };
    evaluate_authenticated(bundle, policy, &rules, contact)
}

/// Stable refusal codes. They never include profile answers, salts or raw gates.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum Refusal {
    /// Malformed or oversized input.
    Malformed,
    /// Invalid snapshot signature, kind, issuer, content, epoch or revision.
    Snapshot,
    /// Snapshot exceeds the caller's maximum age.
    StaleSnapshot,
    /// Invalid credential signature or signed lifetime.
    Credential,
    /// Community or member binding differs.
    Subject,
    /// Credential, policy and schema epochs or versions differ.
    Version,
    /// Credential or policy contains malformed or duplicate metadata.
    Metadata,
    /// Member or device is currently revoked.
    Revoked,
    /// Device is not certified by the signed credential.
    UnauthorizedDevice,
    /// Device signature does not authenticate this complete payload.
    Binding,
    /// A gate is absent, expired or issued by a disallowed provider.
    Gate,
    /// Handle is invalid or noncanonical.
    Handle,
    /// cshm validation failed, with schema-declared field names only.
    Profile(Vec<cshm::Violation>),
    /// A required pin or opening is absent, unexpected, duplicated or incorrect.
    Pin,
}

/// The portion of the profile actually checked by an admission.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Public fields only; no assertion about hidden private values.
    Public,
    /// Both public and private fields.
    Full,
}

/// Admission result. Refusal reasons follow fixed evaluation order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Admission {
    /// Every applicable check passed.
    Admitted {
        /// Authenticated community.
        community: String,
        /// Authenticated member pseudonym.
        member: String,
        /// Validated schema version.
        schema_version: u32,
        /// Validated profile scope.
        scope: Scope,
    },
    /// One or more checks failed; no admission is implied.
    Refused {
        /// Stable, value-free reasons.
        reasons: Vec<Refusal>,
    },
}

impl Admission {
    /// Whether all checks passed.
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }
}

/// Verify a bound presentation against signed settings and an exact schema.
/// Fields requiring contact detection fail closed unless [`check_with_contact`]
/// is used. This function performs no I/O, reads no clock and stores nothing.
pub fn check(bundle: &Bundle, policy: &Policy<'_>, schema: &[u8]) -> Admission {
    check_with_contact(bundle, policy, schema, &|_| cshm::ContactCheck::Unavailable)
}

/// As [`check`], with a caller's deterministic contact-details detector.
pub fn check_with_contact(
    bundle: &Bundle,
    policy: &Policy<'_>,
    schema: &[u8],
    contact: &dyn Fn(&str) -> cshm::ContactCheck,
) -> Admission {
    match evaluate(bundle, policy, schema, contact) {
        Ok(admission) => admission,
        Err(reason) => Admission::Refused {
            reasons: vec![reason],
        },
    }
}

pub(crate) fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Refusal> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Refusal::Malformed);
    }
    serde_json::from_slice(bytes).map_err(|_| Refusal::Malformed)
}

pub(crate) fn snapshot<T: DeserializeOwned>(
    bytes: &[u8],
    community: &str,
    keys: &KeyRing,
    kind: Kind,
    now: u64,
) -> Result<(Snapshot<T>, u64), Refusal> {
    if bytes.len() > MAX_DOCUMENT_BYTES || keys.issuer() != community {
        return Err(Refusal::Snapshot);
    }
    let signed = keys
        .verify(bytes, kind, now)
        .map_err(|_| Refusal::Snapshot)?;
    let snapshot: Snapshot<T> = parse(signed.payload()).map_err(|_| Refusal::Snapshot)?;
    if snapshot.community != community || snapshot.revision == 0 {
        return Err(Refusal::Snapshot);
    }
    Ok((snapshot, signed.issued_at()))
}

pub(crate) fn valid_settings(settings: &Settings) -> bool {
    settings.required_gates.len() <= MAX_ITEMS
        && settings.revoked_members.len() <= MAX_ITEMS
        && settings.revoked_devices.len() <= MAX_ITEMS
        && settings.reserved_handles.len() <= MAX_ITEMS
        && unique(settings.required_gates.iter().map(|g| &g.gate))
        && settings.required_gates.iter().all(|g| {
            identifier(&g.gate)
                && !g.providers.is_empty()
                && g.providers.len() <= MAX_ITEMS
                && unique(g.providers.iter())
                && g.providers.iter().all(|p| identifier(p))
        })
        && settings.revoked_members.iter().all(|m| identifier(m))
        && unique(settings.revoked_members.iter())
        && unique(settings.revoked_devices.iter())
}

fn unique<T: Ord>(items: impl Iterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    items.into_iter().all(|item| seen.insert(item))
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn evaluate(
    bundle: &Bundle,
    policy: &Policy<'_>,
    schema_bytes: &[u8],
    contact: &dyn Fn(&str) -> cshm::ContactCheck,
) -> Result<Admission, Refusal> {
    let (settings, settings_issued) = snapshot::<Settings>(
        policy.settings,
        policy.community,
        policy.keys,
        Kind::SettingsSnapshot,
        policy.now,
    )?;
    let (schema, schema_issued) = snapshot::<cshm::Schema>(
        schema_bytes,
        policy.community,
        policy.keys,
        Kind::SchemaSnapshot,
        policy.now,
    )?;
    if settings.revision < policy.minimum_settings_revision
        || schema.revision < policy.minimum_schema_revision
        || settings.policy_epoch < policy.minimum_epoch
        || settings.policy_epoch != schema.policy_epoch
        || schema.content.community != policy.community
    {
        return Err(Refusal::Snapshot);
    }
    if policy.now.saturating_sub(settings_issued) > policy.maximum_snapshot_age
        || policy.now.saturating_sub(schema_issued) > policy.maximum_snapshot_age
    {
        return Err(Refusal::StaleSnapshot);
    }
    if !valid_settings(&settings.content)
        || schema.content.public.len() + schema.content.private.len() > MAX_ITEMS
    {
        return Err(Refusal::Metadata);
    }
    let rules = VerifiedRules {
        epoch: settings.policy_epoch,
        schema: schema.content,
        revocations: Revocations {
            members: settings.content.revoked_members.into_iter().collect(),
            devices: settings.content.revoked_devices.into_iter().collect(),
        },
        reserved_handles: settings.content.reserved_handles,
        gates: GatePolicy::Legacy(settings.content.required_gates),
    };
    evaluate_authenticated(bundle, policy, &rules, contact)
}

fn evaluate_authenticated(
    bundle: &Bundle,
    policy: &Policy<'_>,
    rules: &VerifiedRules,
    contact: &dyn Fn(&str) -> cshm::ContactCheck,
) -> Result<Admission, Refusal> {
    let compiled = rules.schema.compile().map_err(|_| Refusal::Snapshot)?;
    let body: BundleContent = parse(&bundle.payload)?;
    // The bounded outer JSON is longer than any decoded credential byte array.
    if body.openings.len() > MAX_ITEMS {
        return Err(Refusal::Malformed);
    }
    let signed = policy
        .keys
        .verify(&body.credential, Kind::Credential, policy.now)
        .map_err(|_| Refusal::Credential)?;
    let credential: Credential = parse(signed.payload()).map_err(|_| Refusal::Credential)?;
    if credential.community != policy.community
        || body.community != policy.community
        || body.member != credential.member
        || !identifier(&credential.member)
    {
        return Err(Refusal::Subject);
    }
    if credential.policy_epoch != rules.epoch || credential.schema_version != rules.schema.version {
        return Err(Refusal::Version);
    }
    if credential.devices.is_empty()
        || credential.devices.len() > MAX_ITEMS
        || credential.pins.len() > MAX_ITEMS
        || credential.gates.len() > MAX_ITEMS
        || !unique(credential.devices.iter())
        || !unique(credential.pins.iter().map(|p| &p.field))
        || !unique(credential.gates.iter().map(|g| &g.gate))
        || credential
            .gates
            .iter()
            .any(|g| !identifier(&g.gate) || !identifier(&g.provider))
    {
        return Err(Refusal::Metadata);
    }
    if rules.revocations.members.contains(&body.member)
        || rules.revocations.devices.contains(&body.device)
    {
        return Err(Refusal::Revoked);
    }
    if !credential.devices.contains(&body.device) {
        return Err(Refusal::UnauthorizedDevice);
    }
    let key = VerifyingKey::from_bytes(&body.device).map_err(|_| Refusal::Binding)?;
    let signature = Signature::from_slice(&bundle.signature).map_err(|_| Refusal::Binding)?;
    key.verify_strict(&binding_bytes(&bundle.payload), &signature)
        .map_err(|_| Refusal::Binding)?;
    if credential
        .gates
        .iter()
        .any(|g| g.valid_until < signed.valid_until())
    {
        return Err(Refusal::Gate);
    }
    rules.gates.check(&credential, policy.now)?;
    let handle =
        check_handle(&credential.handle, &rules.reserved_handles).map_err(|_| Refusal::Handle)?;
    if handle.normalized != credential.handle {
        return Err(Refusal::Handle);
    }
    let report = match &body.profile {
        Profile::Public(p) => compiled.validate_public_with(p, &contact),
        Profile::Full(p) => compiled.validate_profile_with(p, &contact),
    };
    if !report.is_valid() {
        return Err(Refusal::Profile(report.violations));
    }
    check_pins(&body, &credential, &rules.schema)?;
    Ok(Admission::Admitted {
        community: credential.community,
        member: credential.member,
        schema_version: credential.schema_version,
        scope: match body.profile {
            Profile::Public(_) => Scope::Public,
            Profile::Full(_) => Scope::Full,
        },
    })
}

fn check_pins(
    body: &BundleContent,
    credential: &Credential,
    schema: &cshm::Schema,
) -> Result<(), Refusal> {
    if !unique(body.openings.iter().map(|o| &o.field)) {
        return Err(Refusal::Pin);
    }
    let all = || schema.public.iter().chain(&schema.private);
    if credential
        .pins
        .iter()
        .any(|p| !all().any(|f| f.id == p.field && f.change_preset != cshm::ChangePreset::Free))
    {
        return Err(Refusal::Pin);
    }
    let mut expected = BTreeSet::new();
    for field in all() {
        if matches!(body.profile, Profile::Public(_))
            && schema.private.iter().any(|f| f.id == field.id)
        {
            continue;
        }
        if field.change_preset == cshm::ChangePreset::Free {
            continue;
        }
        let pin = credential.pins.iter().find(|p| p.field == field.id);
        let value = body.profile.answer(&field.id);
        if pin.is_none() && value.is_none() {
            continue;
        }
        let (Some(pin), Some(value)) = (pin, value) else {
            return Err(Refusal::Pin);
        };
        let opening = body
            .openings
            .iter()
            .find(|o| o.field == field.id)
            .ok_or(Refusal::Pin)?;
        if opening.salt.len() > 1024 {
            return Err(Refusal::Pin);
        }
        let salt = cpns::Salt::from_bytes(opening.salt.clone()).map_err(|_| Refusal::Pin)?;
        let context = cpns::FingerprintContext {
            community: &credential.community,
            member: &credential.member,
            field: &field.id,
        };
        if !cpns::check_opening_v2(
            &cpns::Fingerprint::from_bytes(pin.fingerprint),
            &context,
            &pin_value_bytes(value),
            &salt,
        ) {
            return Err(Refusal::Pin);
        }
        expected.insert(&field.id);
    }
    if body.openings.iter().any(|o| !expected.contains(&o.field)) {
        return Err(Refusal::Pin);
    }
    Ok(())
}
