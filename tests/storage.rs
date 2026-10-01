//! Real libSQL and memory-store contract tests; never build storage on wasm.
#![cfg(all(feature = "storage", not(target_arch = "wasm32")))]
mod common;

use cgrd::storage::*;
use common::*;
use crlt::{Config, Db, Migration};

fn record(community: &str, revision: u64, epoch: u64) -> SnapshotRecord {
    let mut issuer = issuer(community);
    let mut payload = settings(community, revision);
    payload.policy_epoch = epoch;
    let bytes = sign(&mut issuer, csgn::Kind::SettingsSnapshot, &payload);
    SnapshotRecord::verify(
        community,
        issuer.key_ring(),
        SnapshotKind::Settings,
        &bytes,
        NOW,
    )
    .unwrap()
}

async fn contract(store: &impl Store, community: &str) {
    assert_eq!(store.load(SnapshotKind::Settings).await.unwrap(), None);
    let initial = record(community, 1, 2);
    store.save(&initial).await.unwrap();
    let saved = store.load(SnapshotKind::Settings).await.unwrap().unwrap();
    assert_eq!((saved.revision, saved.policy_epoch), (1, 2));
    // Reverification of cached bytes uses the same real signing implementation.
    let mut signer = issuer(community);
    sign(
        &mut signer,
        csgn::Kind::SettingsSnapshot,
        &settings(community, 1),
    );
    SnapshotRecord::verify(
        community,
        signer.key_ring(),
        SnapshotKind::Settings,
        &saved.cose,
        NOW,
    )
    .unwrap();
    store.save(&initial).await.unwrap();
    assert_eq!(
        store.load(SnapshotKind::Settings).await.unwrap(),
        Some(saved.clone())
    );
    assert_eq!(
        store.save(&record(community, 1, 3)).await,
        Err(StorageError::Conflict)
    );
    assert_eq!(
        store.save(&record(community, 2, 1)).await,
        Err(StorageError::Conflict)
    );
    assert_eq!(
        store.load(SnapshotKind::Settings).await.unwrap(),
        Some(saved)
    );
    store.save(&record(community, 3, 3)).await.unwrap();
    assert_eq!(
        store.save(&record(community, 2, 3)).await,
        Err(StorageError::Conflict)
    );
    assert_eq!(
        store.save(&record("another-community", 4, 3)).await,
        Err(StorageError::Invalid)
    );
    assert_eq!(
        store
            .load(SnapshotKind::Settings)
            .await
            .unwrap()
            .unwrap()
            .revision,
        3
    );
    assert_eq!(store.load(SnapshotKind::Schema).await.unwrap(), None);
    let schema = cgrd::Snapshot {
        community: community.into(),
        revision: 1,
        policy_epoch: 3,
        content: schema(community),
    };
    let bytes = sign(&mut signer, csgn::Kind::SchemaSnapshot, &schema);
    let schema = SnapshotRecord::verify(
        community,
        signer.key_ring(),
        SnapshotKind::Schema,
        &bytes,
        NOW,
    )
    .unwrap();
    store.save(&schema).await.unwrap();
    assert_eq!(
        store
            .load(SnapshotKind::Schema)
            .await
            .unwrap()
            .unwrap()
            .cose,
        bytes
    );
}

#[tokio::test]
async fn memory_contract() {
    contract(&MemoryStore::new("memory").unwrap(), "memory").await;
    assert!(MemoryStore::new("").is_err());
}

#[tokio::test]
async fn libsql_round_trip_reopen_isolation_and_query_plans() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("guard.db").display());
    let db = Db::open(Config::new(&url, "")).await.unwrap();
    let migrations = [Migration::new(1, "guard snapshots", SCHEMA)];
    assert_eq!(db.migrate(&migrations).await.unwrap(), 1);
    assert_eq!(db.migrate(&migrations).await.unwrap(), 0);
    let a = LibsqlStore::new(&db, "a").unwrap();
    let b = LibsqlStore::new(&db, "b").unwrap();
    a.check_query_plans().await.unwrap();
    contract(&a, "a").await;
    assert_eq!(b.load(SnapshotKind::Settings).await.unwrap(), None);
    contract(&b, "b").await;
    assert_ne!(
        a.load(SnapshotKind::Settings).await.unwrap(),
        b.load(SnapshotKind::Settings).await.unwrap()
    );
    drop(a);
    drop(b);
    drop(db);
    let reopened = Db::open(Config::new(url, "")).await.unwrap();
    reopened.migrate(&migrations).await.unwrap();
    assert_eq!(
        LibsqlStore::new(&reopened, "a")
            .unwrap()
            .load(SnapshotKind::Settings)
            .await
            .unwrap()
            .unwrap()
            .revision,
        3
    );
}

#[tokio::test]
async fn concurrent_stores_cannot_overwrite_a_newer_revision() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(Config::new(
        format!("file://{}", dir.path().join("concurrent.db").display()),
        "",
    ))
    .await
    .unwrap();
    db.migrate(&[Migration::new(1, "guard snapshots", SCHEMA)])
        .await
        .unwrap();
    let a = LibsqlStore::new(&db, "a").unwrap();
    let b = a.clone();
    a.save(&record("a", 1, 2)).await.unwrap();
    let two = record("a", 2, 2);
    let three = record("a", 3, 2);
    let (older, newer) = tokio::join!(a.save(&two), b.save(&three));
    assert!(older.is_ok() || older == Err(StorageError::Conflict));
    newer.unwrap();
    assert_eq!(
        a.load(SnapshotKind::Settings)
            .await
            .unwrap()
            .unwrap()
            .revision,
        3
    );
}

#[tokio::test]
async fn storage_failures_are_redacted_and_unsigned_payloads_cannot_be_cached() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(Config::new(
        format!("file://{}", dir.path().join("unmigrated.db").display()),
        "",
    ))
    .await
    .unwrap();
    let store = LibsqlStore::new(&db, "a").unwrap();
    assert_eq!(
        store.save(&record("a", 1, 2)).await,
        Err(StorageError::Unavailable)
    );
    assert_eq!(
        store.load(SnapshotKind::Settings).await,
        Err(StorageError::Unavailable)
    );
    let mut signer = issuer("a");
    let bytes = sign(&mut signer, csgn::Kind::Credential, &settings("a", 1));
    assert!(matches!(
        SnapshotRecord::verify("a", signer.key_ring(), SnapshotKind::Settings, &bytes, NOW),
        Err(StorageError::Invalid)
    ));
    let bytes = sign(&mut signer, csgn::Kind::SettingsSnapshot, &settings("a", 1));
    assert!(matches!(
        SnapshotRecord::verify("b", signer.key_ring(), SnapshotKind::Settings, &bytes, NOW),
        Err(StorageError::Invalid)
    ));
    assert!(matches!(
        SnapshotRecord::verify(
            "a",
            signer.key_ring(),
            SnapshotKind::Settings,
            &bytes,
            EXPIRY
        ),
        Err(StorageError::Invalid)
    ));
    assert_eq!(
        StorageError::Unavailable.to_string(),
        "snapshot storage unavailable"
    );
}

#[tokio::test]
async fn turso_round_trip_when_both_credentials_are_present() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        eprintln!("skipping live Turso: both environment credentials are required");
        return;
    };
    if url.is_empty() || token.is_empty() {
        eprintln!("skipping live Turso: both environment credentials must be nonempty");
        return;
    }
    // Errors deliberately discard remote URLs and credentials, even on failure.
    let db = Db::open(Config::new(url, token))
        .await
        .map_err(|_| "Turso open failed")
        .unwrap();
    db.migrate(&[Migration::new(1, "guard snapshots", SCHEMA)])
        .await
        .map_err(|_| "Turso migration failed")
        .unwrap();
    let nonce = tempfile::NamedTempFile::new().unwrap();
    let community = format!(
        "cgrd-{}",
        nonce.path().file_name().unwrap().to_string_lossy()
    );
    let store = LibsqlStore::new(&db, &community).unwrap();
    store.check_query_plans().await.unwrap();
    contract(&store, &community).await;
}

#[tokio::test]
async fn corrupted_database_rows_and_ignored_writes_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(Config::new(
        format!("file://{}", dir.path().join("damaged.db").display()),
        "",
    ))
    .await
    .unwrap();
    assert!(LibsqlStore::new(&db, "bad\ncommunity").is_err());
    // A real database with a damaged/older schema; readers must still enforce
    // the signed record limits instead of trusting SQLite column declarations.
    let schema = SCHEMA
        .replace(" CHECK (revision > 0)", "")
        .replace(" CHECK (policy_epoch >= 0)", "");
    db.migrate(&[Migration::new(1, "damaged schema", &schema)])
        .await
        .unwrap();
    for (name, revision, epoch, cose) in [
        ("zero", 0, 0, vec![1]),
        ("negative", 1, -1, vec![1]),
        ("large", 1, 0, vec![1; cgrd::MAX_DOCUMENT_BYTES + 1]),
    ] {
        db.community(name).unwrap().execute("INSERT INTO cgrd_snapshots (kind, revision, policy_epoch, cose) VALUES (?1, ?2, ?3, ?4)",crlt::params!["settings",revision as i64,epoch as i64,cose]).await.unwrap();
        assert_eq!(
            LibsqlStore::new(&db, name)
                .unwrap()
                .load(SnapshotKind::Settings)
                .await,
            Err(StorageError::Invalid)
        );
    }
    db.community("text").unwrap().execute("INSERT INTO cgrd_snapshots (kind, revision, policy_epoch, cose) VALUES (?1, ?2, ?3, ?4)",crlt::params!["settings",1i64,0i64,"not a blob"]).await.unwrap();
    assert_eq!(
        LibsqlStore::new(&db, "text")
            .unwrap()
            .load(SnapshotKind::Settings)
            .await,
        Err(StorageError::Invalid)
    );
    // crlt correctly rejects trigger migrations. Inject on-disk corruption
    // through the real upstream engine, then exercise Guard through crlt.
    let raw = libsql::Builder::new_local(dir.path().join("damaged.db"))
        .build()
        .await
        .unwrap();
    raw.connect()
        .unwrap()
        .execute_batch("CREATE TRIGGER refuse_snapshot BEFORE INSERT ON cgrd_snapshots BEGIN SELECT RAISE(IGNORE); END;")
        .await
        .unwrap();
    assert_eq!(
        LibsqlStore::new(&db, "ignored")
            .unwrap()
            .save(&record("ignored", 1, 1))
            .await,
        Err(StorageError::Conflict)
    );
}
