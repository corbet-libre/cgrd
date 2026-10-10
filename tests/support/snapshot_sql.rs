//! Caller-side persistence example used only by integration tests, never linked into cgrd.
use cgrd::storage::*;

/// DDL for the service's ordered crlt migration list. No timestamps, member
/// profiles or request data. Primary key covers every lookup and mutation.
pub const SCHEMA: &str = "
CREATE TABLE cgrd_snapshots (
    community_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('settings', 'schema')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    policy_epoch INTEGER NOT NULL CHECK (policy_epoch >= 0),
    cose BLOB NOT NULL,
    PRIMARY KEY (community_id, kind)
) WITHOUT ROWID;
";

const SELECT: &str = "SELECT revision, policy_epoch, cose FROM cgrd_snapshots WHERE kind = ?1";
const INSERT: &str =
    "INSERT INTO cgrd_snapshots (kind, revision, policy_epoch, cose) VALUES (?1, ?2, ?3, ?4)";
const UPDATE: &str = "UPDATE cgrd_snapshots SET revision = ?1, policy_epoch = ?2, cose = ?3 WHERE kind = ?4 AND revision = ?5";

/// Native libSQL implementation through the shared crlt facade.
/// The service supplies a database and owns migrations and credentials.
#[derive(Clone)]
pub struct LibsqlStore {
    community: String,
    db: crlt::Community,
}

impl LibsqlStore {
    /// Bind to one community in an already migrated database.
    pub fn new(db: &crlt::Db, community: &str) -> Result<Self, StorageError> {
        if MemoryStore::new(community).is_err() {
            return Err(StorageError::Invalid);
        }
        let db = db.community(community).map_err(unavailable)?;
        Ok(Self {
            community: community.into(),
            db,
        })
    }

    /// Assert index-backed plans for every statement used by the adapter.
    pub async fn check_query_plans(&self) -> Result<(), StorageError> {
        self.db
            .explain(SELECT, ["settings"])
            .await
            .map_err(unavailable)?
            .assert_indexed()
            .map_err(unavailable)?;
        self.db
            .explain(
                INSERT,
                crlt::params!["settings", 1i64, 0i64, Vec::<u8>::new()],
            )
            .await
            .map_err(unavailable)?
            .assert_indexed()
            .map_err(unavailable)?;
        self.db
            .explain(
                UPDATE,
                crlt::params![2i64, 0i64, Vec::<u8>::new(), "settings", 1i64],
            )
            .await
            .map_err(unavailable)?
            .assert_indexed()
            .map_err(unavailable)?;
        Ok(())
    }
}

fn unavailable(_: crlt::Error) -> StorageError {
    StorageError::Unavailable
}

fn decode(rows: &[crlt::Row]) -> Result<Option<StoredSnapshot>, StorageError> {
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let revision = row.get_i64(0).map_err(unavailable)?;
    let epoch = row.get_i64(1).map_err(unavailable)?;
    let crlt::Value::Blob(bytes) = row.get_value(2).map_err(unavailable)? else {
        return Err(StorageError::Invalid);
    };
    if revision <= 0 || epoch < 0 || bytes.len() > cgrd::MAX_DOCUMENT_BYTES {
        return Err(StorageError::Invalid);
    }
    Ok(Some(StoredSnapshot {
        revision: revision as u64,
        policy_epoch: epoch as u64,
        cose: bytes.clone(),
    }))
}

impl Store for LibsqlStore {
    async fn load(&self, kind: SnapshotKind) -> Result<Option<StoredSnapshot>, StorageError> {
        decode(
            &self
                .db
                .query(SELECT, [kind.as_str()])
                .await
                .map_err(unavailable)?,
        )
    }

    async fn save(&self, record: &SnapshotRecord) -> Result<(), StorageError> {
        if record.community() != self.community {
            return Err(StorageError::Invalid);
        }
        let mut tx = self.db.tx().await.map_err(unavailable)?;
        let current = decode(
            &tx.query(SELECT, [record.kind().as_str()])
                .await
                .map_err(unavailable)?,
        )?;
        let next = record.stored();
        match record.check_replacement(current.as_ref()) {
            Ok(false) => {
                tx.rollback().await.map_err(unavailable)?;
                return Ok(());
            }
            Err(error) => {
                tx.rollback().await.map_err(unavailable)?;
                return Err(error);
            }
            Ok(true) => {}
        }
        let changed = if let Some(current) = current {
            tx.execute(
                UPDATE,
                crlt::params![
                    next.revision as i64,
                    next.policy_epoch as i64,
                    next.cose.clone(),
                    record.kind().as_str(),
                    current.revision as i64
                ],
            )
            .await
        } else {
            tx.execute(
                INSERT,
                crlt::params![
                    record.kind().as_str(),
                    next.revision as i64,
                    next.policy_epoch as i64,
                    next.cose.clone()
                ],
            )
            .await
        }
        .map_err(unavailable)?;
        if changed != 1 {
            tx.rollback().await.map_err(unavailable)?;
            return Err(StorageError::Conflict);
        }
        tx.commit().await.map_err(unavailable)
    }
}
