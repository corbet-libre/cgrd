use std::collections::BTreeMap;

use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
use geographiclib_rs::{Geodesic, InverseGeodesic};
use cshm::{FieldType, PublicProfile, Schema};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{MAX_DOCUMENT_BYTES, MAX_ITEMS};

/// Personal rules are conjunctive. No scripting, private attributes or I/O.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Rule {
    /// Typed equality; numeric and location comparisons are exact decimals.
    Equal {
        /// Public, filterable schema field.
        field: String,
        /// Value of that field's declared type.
        value: Value,
    },
    /// Inclusive numeric interval. Bounds are decimal strings.
    NumberRange {
        /// Public, filterable integer or decimal field.
        field: String,
        /// Inclusive minimum.
        min: String,
        /// Inclusive maximum.
        max: String,
    },
    /// Inclusive WGS84 geodesic distance from the owner's value of the same field.
    DistanceRange {
        /// Public, filterable location field, also present in the owner's profile.
        field: String,
        /// Inclusive minimum distance in meters, as a nonnegative decimal string.
        min_meters: String,
        /// Inclusive maximum distance in meters, as a nonnegative decimal string.
        max_meters: String,
    },
    /// Any of these declared choice identifiers.
    OneOf {
        /// Public, filterable choice field.
        field: String,
        /// Nonempty list of permitted option identifiers.
        values: Vec<String>,
    },
    /// Never match this member; independent of profile attributes.
    Block {
        /// Community pseudonym.
        member: String,
    },
}

/// Construction errors fail closed; they never echo unknown field names/values.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleError {
    /// Invalid member, schema, profile or contact check.
    Profile,
    /// Too many rules/fields or oversized serialization.
    Limit,
    /// A referenced field is private, absent or not filterable.
    NotFilterable,
    /// Wrong operator, type, choice or numeric representation.
    Type,
    /// Empty, inverted or otherwise invalid rule.
    Invalid,
}

#[derive(Clone, PartialEq)]
enum Attribute {
    Number(BigDecimal),
    Boolean(bool),
    Text(String),
    Location(BigDecimal, BigDecimal),
}

enum Predicate {
    Equal(String, Attribute),
    Range(String, BigDecimal, BigDecimal),
    Distance(String, BigDecimal, BigDecimal, BigDecimal, BigDecimal),
    OneOf(String, Vec<String>),
    Block(String),
}

/// Validated public attributes and compiled personal rules for one member.
/// Construction validates data, not identity: authenticate the profile with
/// [`crate::check`] before using a participant for a security decision.
pub struct Participant {
    member: String,
    schema: Schema,
    attributes: BTreeMap<String, Attribute>,
    rules: Vec<Predicate>,
}

impl Participant {
    /// Validate a public profile and compile its owner's rules.
    pub fn new(
        member: &str,
        profile: &PublicProfile,
        schema: &Schema,
        rules: &[Rule],
    ) -> Result<Self, RuleError> {
        Self::with_contact(member, profile, schema, rules, &|_| {
            cshm::ContactCheck::Unavailable
        })
    }

    /// As [`Self::new`], with the same deterministic detector used for admission.
    pub fn with_contact(
        member: &str,
        profile: &PublicProfile,
        schema: &Schema,
        rules: &[Rule],
        contact: &dyn Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Self, RuleError> {
        if rules.len() > MAX_ITEMS
            || schema.public.len() + schema.private.len() > MAX_ITEMS
            || serde_json::to_vec(&(profile, schema, rules))
                .map_err(|_| RuleError::Type)?
                .len()
                > MAX_DOCUMENT_BYTES
        {
            return Err(RuleError::Limit);
        }
        let compiled = schema.compile().map_err(|_| RuleError::Profile)?;
        if !crate::guard::identifier(member)
            || !compiled.validate_public_with(profile, &contact).is_valid()
        {
            return Err(RuleError::Profile);
        }
        let mut attributes = BTreeMap::new();
        for field in schema.public.iter().filter(|f| f.filterable) {
            if let Some(value) = profile.public.get(&field.id) {
                attributes.insert(field.id.clone(), attribute(&field.kind, value)?);
            }
        }
        let rules = rules
            .iter()
            .map(|rule| compile_rule(rule, schema, &attributes))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            member: member.into(),
            schema: schema.clone(),
            attributes,
            rules,
        })
    }
}

fn number(text: &str) -> Result<BigDecimal, RuleError> {
    cshm::parse_number(text).map_err(|_| RuleError::Type)
}

fn json_number(value: &Value) -> Result<BigDecimal, RuleError> {
    if !value.is_number() {
        return Err(RuleError::Type);
    }
    number(&value.to_string())
}

fn attribute(kind: &FieldType, value: &Value) -> Result<Attribute, RuleError> {
    match kind {
        FieldType::Integer { .. } => {
            let n = json_number(value)?;
            if !n.is_integer() {
                return Err(RuleError::Type);
            }
            Ok(Attribute::Number(n))
        }
        FieldType::Decimal { .. } => Ok(Attribute::Number(json_number(value)?)),
        FieldType::YesNo => value
            .as_bool()
            .map(Attribute::Boolean)
            .ok_or(RuleError::Type),
        FieldType::Choice { options } => {
            let text = value.as_str().ok_or(RuleError::Type)?;
            if !options.iter().any(|o| o.id == text) {
                return Err(RuleError::Type);
            }
            Ok(Attribute::Text(text.into()))
        }
        FieldType::ShortText { .. } | FieldType::LongText { .. } => value
            .as_str()
            .map(|s| Attribute::Text(s.into()))
            .ok_or(RuleError::Type),
        FieldType::Location => {
            let object = value.as_object().ok_or(RuleError::Type)?;
            if object.len() != 2 {
                return Err(RuleError::Type);
            }
            let lat = json_number(object.get("latitude").ok_or(RuleError::Type)?)?;
            let lon = json_number(object.get("longitude").ok_or(RuleError::Type)?)?;
            let latitude = BigDecimal::from(-90)..=BigDecimal::from(90);
            let longitude = BigDecimal::from(-180)..=BigDecimal::from(180);
            if !latitude.contains(&lat) || !longitude.contains(&lon) {
                return Err(RuleError::Type);
            }
            Ok(Attribute::Location(lat, lon))
        }
    }
}

fn compile_rule(
    rule: &Rule,
    schema: &Schema,
    attributes: &BTreeMap<String, Attribute>,
) -> Result<Predicate, RuleError> {
    let field = |id: &str| {
        schema
            .public
            .iter()
            .find(|f| f.id == id && f.filterable)
            .ok_or(RuleError::NotFilterable)
    };
    match rule {
        Rule::Equal { field: id, value } => Ok(Predicate::Equal(
            id.clone(),
            attribute(&field(id)?.kind, value)?,
        )),
        Rule::NumberRange {
            field: id,
            min,
            max,
        } => {
            if !matches!(
                field(id)?.kind,
                FieldType::Integer { .. } | FieldType::Decimal { .. }
            ) {
                return Err(RuleError::Type);
            }
            let (min, max) = (number(min)?, number(max)?);
            if min > max {
                return Err(RuleError::Invalid);
            }
            Ok(Predicate::Range(id.clone(), min, max))
        }
        Rule::DistanceRange { field: id, min_meters, max_meters } => {
            if !matches!(field(id)?.kind, FieldType::Location) {
                return Err(RuleError::Type);
            }
            let (min, max) = (number(min_meters)?, number(max_meters)?);
            if min < BigDecimal::from(0) || min > max {
                return Err(RuleError::Invalid);
            }
            let Some(Attribute::Location(latitude, longitude)) = attributes.get(id) else {
                return Err(RuleError::Profile);
            };
            Ok(Predicate::Distance(id.clone(), latitude.clone(), longitude.clone(), min, max))
        }
        Rule::OneOf { field: id, values } => {
            let FieldType::Choice { options } = &field(id)?.kind else {
                return Err(RuleError::Type);
            };
            if values.is_empty() || values.len() > MAX_ITEMS {
                return Err(RuleError::Invalid);
            }
            if values.iter().any(|v| !options.iter().any(|o| o.id == *v)) {
                return Err(RuleError::Type);
            }
            Ok(Predicate::OneOf(id.clone(), values.clone()))
        }
        Rule::Block { member } => {
            if crate::guard::identifier(member) {
                Ok(Predicate::Block(member.clone()))
            } else {
                Err(RuleError::Invalid)
            }
        }
    }
}

/// Owner of a failing rule, relative to `matches(a, b)`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// First participant.
    A,
    /// Second participant.
    B,
}

/// Why a pair fails to match; no rule bounds or profile values are disclosed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchReason {
    /// Communities or complete schema definitions differ.
    Schema,
    /// A member was paired with itself.
    SameMember,
    /// An explicit block applies.
    Blocked,
    /// A rule's target field has no answer.
    Missing,
    /// Typed equality or a choice set failed.
    Different,
    /// A number falls outside an inclusive interval.
    OutsideRange,
}

/// Owner-facing explanation; the owner can resolve `rule_index` in its rules.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatchFailure {
    /// Rule owner, absent for a pair-level failure.
    pub owner: Option<Side>,
    /// Zero-based rule position, absent for a pair-level failure.
    pub rule_index: Option<usize>,
    /// Declared public field, absent for blocks and pair-level failures.
    pub field: Option<String>,
    /// Stable reason without values.
    pub reason: MatchReason,
}

/// Reciprocal matching result in A-rule order followed by B-rule order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatchResult {
    /// Empty exactly when both participants accept each other.
    pub failures: Vec<MatchFailure>,
}

impl MatchResult {
    /// Whether both directions passed.
    pub fn is_match(&self) -> bool {
        self.failures.is_empty()
    }

    /// Requester-safe disclosure: only failing field names, in sorted order.
    /// Blocks and pair-level failures yield no field; use a generic refusal.
    pub fn requester_fields(&self) -> Vec<String> {
        self.failures
            .iter()
            .filter_map(|f| f.field.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Evaluate both sets of rules. Missing fields always fail, even equality
/// against null. A block in either direction prevents a match.
pub fn matches(a: &Participant, b: &Participant) -> MatchResult {
    let pair_reason = if a.schema != b.schema {
        Some(MatchReason::Schema)
    } else if a.member == b.member {
        Some(MatchReason::SameMember)
    } else {
        None
    };
    if let Some(reason) = pair_reason {
        return MatchResult {
            failures: vec![MatchFailure {
                owner: None,
                rule_index: None,
                field: None,
                reason,
            }],
        };
    }
    let mut failures = Vec::new();
    for (owner, source, target) in [(Side::A, a, b), (Side::B, b, a)] {
        for (index, rule) in source.rules.iter().enumerate() {
            let (field, reason) = evaluate_rule(rule, target);
            if let Some(reason) = reason {
                failures.push(MatchFailure {
                    owner: Some(owner),
                    rule_index: Some(index),
                    field: field.cloned(),
                    reason,
                });
            }
        }
    }
    MatchResult { failures }
}

fn evaluate_rule<'a>(
    rule: &'a Predicate,
    target: &Participant,
) -> (Option<&'a String>, Option<MatchReason>) {
    match rule {
        Predicate::Equal(field, expected) => compare_attribute(target, field, &|value| {
            (value != expected).then_some(MatchReason::Different)
        }),
        Predicate::Range(field, min, max) => {
            compare_attribute(target, field, &|value| match value {
                Attribute::Number(n) => (n < min || n > max).then_some(MatchReason::OutsideRange),
                _ => Some(MatchReason::Different),
            })
        }
        Predicate::Distance(field, latitude, longitude, min, max) => {
            compare_attribute(target, field, &|value| match value {
                Attribute::Location(other_latitude, other_longitude) => {
                    let meters: f64 = Geodesic::wgs84().inverse(
                        latitude.to_f64().unwrap_or(f64::NAN),
                        longitude.to_f64().unwrap_or(f64::NAN),
                        other_latitude.to_f64().unwrap_or(f64::NAN),
                        other_longitude.to_f64().unwrap_or(f64::NAN),
                    );
                    BigDecimal::from_f64(meters).map_or(Some(MatchReason::Different), |distance| {
                        (distance < *min || distance > *max).then_some(MatchReason::OutsideRange)
                    })
                }
                _ => Some(MatchReason::Different),
            })
        }
        Predicate::OneOf(field, values) => compare_attribute(target, field, &|value| match value {
            Attribute::Text(text) => (!values.contains(text)).then_some(MatchReason::Different),
            _ => Some(MatchReason::Different),
        }),
        Predicate::Block(member) => (
            None,
            (member == &target.member).then_some(MatchReason::Blocked),
        ),
    }
}

fn compare_attribute<'a>(
    target: &Participant,
    field: &'a String,
    compare: &dyn Fn(&Attribute) -> Option<MatchReason>,
) -> (Option<&'a String>, Option<MatchReason>) {
    let reason = target
        .attributes
        .get(field)
        .map_or(Some(MatchReason::Missing), compare);
    (Some(field), reason)
}

#[cfg(test)]
#[path = "../tests/unit/matching.rs"]
mod unit_tests;
