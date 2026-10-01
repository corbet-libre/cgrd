use super::*;

#[tokio::test]
async fn poisoned_memory_storage_refuses_reads_and_verified_writes() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/admission.json")).unwrap();
    let bytes: Vec<u8> = serde_json::from_value(vector["settings"].clone()).unwrap();
    let ring: Vec<u8> = serde_json::from_value(vector["keys"].clone()).unwrap();
    let keys = KeyRing::from_cbor(&ring).unwrap();
    let record =
        SnapshotRecord::verify("garden", &keys, SnapshotKind::Settings, &bytes, 1100).unwrap();
    let store = MemoryStore::new("garden").unwrap();
    let rows = store.rows.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = rows.lock().unwrap();
            panic!("interrupt an actual held storage lock");
        })
        .join()
        .is_err()
    );
    assert_eq!(
        store.load(SnapshotKind::Settings).await,
        Err(StorageError::Unavailable)
    );
    assert_eq!(store.save(&record).await, Err(StorageError::Unavailable));
}
