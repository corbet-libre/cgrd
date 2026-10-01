//! Optional storage for signed public settings/schema snapshots only.
//! Admission and matching never call this API. Reverify loaded COSE bytes
//! against the current caller trust inputs before use; a cache is not a root.

use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, Mutex},
};

use csgn::{KeyRing, Kind};

use crate::{Settings, guard};

#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
mod libsql;
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
pub use libsql::{LibsqlStore, SCHEMA};

/// Public snapshot types this cache is allowed to retain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SnapshotKind {
    /// Resolved settings, including the current revocation state.
    Settings,
    /// Profile schema.
    Schema,
}

impl SnapshotKind {
    /// csgn protected kind corresponding to the stored snapshot.
    pub fn cose_kind(self) -> Kind {
        match self {
            Self::Settings => Kind::SettingsSnapshot,
            Self::Schema => Kind::SchemaSnapshot,
        }
    }

    /// Stable database key.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Settings => "settings",
            Self::Schema => "schema",
        }
    }
}

/// Cached bytes and metadata. Loading does not authenticate or refresh them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSnapshot {
    /// Positive signed revision.
    pub revision: u64,
    /// Signed admission epoch.
    pub policy_epoch: u64,
    /// Original COSE bytes; always reverify when used.
    pub cose: Vec<u8>,
}

/// A signature-checked public snapshot. Private fields prevent accidental
/// insertion of bundles, credentials, openings, or arbitrary byte payloads.
pub struct SnapshotRecord {
    community: String,
    kind: SnapshotKind,
    stored: StoredSnapshot,
}

impl SnapshotRecord {
    /// Verify a public snapshot and its content before allowing persistence.
    pub fn verify(
        community: &str,
        keys: &KeyRing,
        kind: SnapshotKind,
        cose: &[u8],
        now: u64,
    ) -> Result<Self, StorageError> {
        let (revision, epoch) = match kind {
            SnapshotKind::Settings => {
                let (s, _) =
                    guard::snapshot::<Settings>(cose, community, keys, kind.cose_kind(), now)
                        .map_err(|_| StorageError::Invalid)?;
                if !guard::valid_settings(&s.content) {
                    return Err(StorageError::Invalid);
                }
                (s.revision, s.policy_epoch)
            }
            SnapshotKind::Schema => {
                let (s, _) =
                    guard::snapshot::<cshm::Schema>(cose, community, keys, kind.cose_kind(), now)
                        .map_err(|_| StorageError::Invalid)?;
                if s.content.community != community
                    || s.content.public.len() + s.content.private.len() > crate::MAX_ITEMS
                {
                    return Err(StorageError::Invalid);
                }
                s.content
                    .validate_definition()
                    .map_err(|_| StorageError::Invalid)?;
                (s.revision, s.policy_epoch)
            }
        };
        if revision > i64::MAX as u64 || epoch > i64::MAX as u64 {
            return Err(StorageError::Invalid);
        }
        Ok(Self {
            community: community.into(),
            kind,
            stored: StoredSnapshot {
                revision,
                policy_epoch: epoch,
                cose: cose.to_vec(),
            },
        })
    }
}

/// Storage failures contain neither SQL, URLs, credentials nor submitted data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StorageError {
    /// Backend failed; a remote write's outcome may be uncertain.
    #[error("snapshot storage unavailable")]
    Unavailable,
    /// Invalid snapshot, metadata or namespace.
    #[error("invalid snapshot or namespace")]
    Invalid,
    /// Revision/epoch rollback or a different value at the same revision.
    #[error("snapshot revision conflict")]
    Conflict,
}

/// Small community-bound cache contract. Saves are atomic and monotonic;
/// replaying exactly the stored bytes is idempotent.
pub trait Store: Send + Sync {
    /// Load the latest snapshot of one kind, with no access timestamps.
    fn load(
        &self,
        kind: SnapshotKind,
    ) -> impl Future<Output = Result<Option<StoredSnapshot>, StorageError>> + Send;
    /// Save only verified public snapshots for this store's community.
    fn save(
        &self,
        record: &SnapshotRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// In-memory implementation of the same cache contract.
#[derive(Clone)]
pub struct MemoryStore {
    community: String,
    rows: Arc<Mutex<BTreeMap<SnapshotKind, StoredSnapshot>>>,
}

impl MemoryStore {
    /// Create an empty store bound to a caller-authorized community.
    pub fn new(community: &str) -> Result<Self, StorageError> {
        if !guard::identifier(community) {
            return Err(StorageError::Invalid);
        }
        Ok(Self {
            community: community.into(),
            rows: Arc::default(),
        })
    }
}

fn should_write(
    current: Option<&StoredSnapshot>,
    next: &StoredSnapshot,
) -> Result<bool, StorageError> {
    if let Some(current) = current {
        if current == next {
            return Ok(false);
        }
        if next.revision <= current.revision || next.policy_epoch < current.policy_epoch {
            return Err(StorageError::Conflict);
        }
    }
    Ok(true)
}

impl Store for MemoryStore {
    async fn load(&self, kind: SnapshotKind) -> Result<Option<StoredSnapshot>, StorageError> {
        Ok(self
            .rows
            .lock()
            .map_err(|_| StorageError::Unavailable)?
            .get(&kind)
            .cloned())
    }

    async fn save(&self, record: &SnapshotRecord) -> Result<(), StorageError> {
        if record.community != self.community {
            return Err(StorageError::Invalid);
        }
        let mut rows = self.rows.lock().map_err(|_| StorageError::Unavailable)?;
        if should_write(rows.get(&record.kind), &record.stored)? {
            rows.insert(record.kind, record.stored.clone());
        }
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/unit/storage.rs"]
mod unit_tests;
