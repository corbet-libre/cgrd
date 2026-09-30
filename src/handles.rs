use precis_profiles::{UsernameCaseMapped, precis_core::profile::PrecisFastInvocation};
use rustrict::CensorStr;
use serde::{Deserialize, Serialize};
use unicode_security::{MixedScript, skeleton};

/// A canonical handle and its uniqueness key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckedHandle {
    /// PRECIS UsernameCaseMapped result.
    pub normalized: String,
    /// UTS #39 confusable skeleton; reserve this atomically per community.
    pub skeleton: String,
}

/// Stable handle refusal reasons in evaluation order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleReason {
    /// Input exceeds the defensive byte budget.
    TooLarge,
    /// PRECIS rejected the input.
    Precis,
    /// Normalized length is outside 8..=32 Unicode scalar values.
    Length,
    /// No single Unicode script covers all non-neutral characters.
    MixedScript,
    /// The maintained profanity filter rejected the normalized handle.
    Profanity,
    /// A caller-supplied reserved handle has the same skeleton.
    Reserved,
    /// A reserved entry is malformed; fail closed rather than ignore it.
    InvalidReserved,
}

/// Normalize, check length, single script, profanity and reserved skeletons.
/// Common/Inherited characters are neutral. This stricter single-script check
/// excludes UTS #39's augmented Japanese/Korean multiscript combinations.
pub fn check_handle(handle: &str, reserved: &[String]) -> Result<CheckedHandle, Vec<HandleReason>> {
    if handle.len() > 4096 {
        return Err(vec![HandleReason::TooLarge]);
    }
    let normalized = UsernameCaseMapped::enforce(handle)
        .map_err(|_| vec![HandleReason::Precis])?
        .into_owned();
    let mut reasons = Vec::new();
    if !(8..=32).contains(&normalized.chars().count()) {
        reasons.push(HandleReason::Length);
    }
    let scripts = normalized.as_str().resolve_script_set();
    if !normalized.as_str().is_single_script() || scripts.base.is_empty() {
        reasons.push(HandleReason::MixedScript);
    }
    if normalized.is_inappropriate() {
        reasons.push(HandleReason::Profanity);
    }
    let key: String = skeleton(&normalized).collect();
    let mut reserved_match = false;
    let mut invalid = reserved.len() > crate::MAX_ITEMS;
    for entry in reserved.iter().take(crate::MAX_ITEMS) {
        if entry.len() > 4096 {
            invalid = true;
            continue;
        }
        match UsernameCaseMapped::enforce(entry.as_str()) {
            Ok(entry) => reserved_match |= skeleton(&entry).eq(key.chars()),
            Err(_) => invalid = true,
        }
    }
    if reserved_match {
        reasons.push(HandleReason::Reserved);
    }
    if invalid {
        reasons.push(HandleReason::InvalidReserved);
    }
    if reasons.is_empty() {
        Ok(CheckedHandle {
            normalized,
            skeleton: key,
        })
    } else {
        Err(reasons)
    }
}
