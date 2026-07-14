use std::fs;
use std::path::Path;

use codeischeap_capture_ipc::{
    CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureSource, CapturedBody, CapturedBodyState,
    CapturedField, CapturedRequest,
};
use codeischeap_capture_policy::{CapturePolicy, SanitizedCapture};
use codeischeap_prompt_ir::PromptIr;
use codeischeap_storage::{CaptureCursor, DatabaseKey, EncryptedStore, SCHEMA_VERSION};
use tempfile::tempdir;

const KEY_BYTES: [u8; 32] = [0x42; 32];
const SECRET_CANARY: &str = "storage-secret-canary";
const PROMPT_CANARY: &str = "encrypted-prompt-canary migration plan";

fn sanitized_capture(id: &str, observed_at: u64, prompt: &str) -> SanitizedCapture {
    let policy = CapturePolicy::load_default().expect("policy must load");
    let envelope = CaptureEnvelope {
        version: CAPTURE_ENVELOPE_VERSION.to_owned(),
        capture_id: id.to_owned(),
        observed_at_unix_ms: observed_at,
        source: CaptureSource::Mitmproxy,
        request: CapturedRequest {
            method: "POST".to_owned(),
            scheme: "https".to_owned(),
            host: "api.openai.com".to_owned(),
            port: 443,
            path: "/v1/responses".to_owned(),
            query: Vec::new(),
            headers: vec![CapturedField {
                name: "authorization".to_owned(),
                value: format!("Bearer {SECRET_CANARY}"),
            }],
            body: CapturedBody {
                state: CapturedBodyState::Json,
                content: Some(serde_json::json!({"input": prompt})),
            },
        },
        redactions: Vec::new(),
    };
    policy
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope")
}

#[test]
fn sqlcipher_wal_fts_and_round_trip_keep_plaintext_off_disk() {
    let directory = tempdir().expect("temp directory must be created");
    let database_path = directory.path().join("captures.db");
    let mut store = EncryptedStore::open(&database_path, DatabaseKey::from_bytes(KEY_BYTES))
        .expect("encrypted store must open");
    let capture = sanitized_capture("capture_1", 1_721_000_000_001, PROMPT_CANARY);
    let mut prompt_ir = PromptIr::new("capture_1", "openai");
    prompt_ir.model = Some("gpt-synthetic".to_owned());

    store
        .upsert_capture(&capture, Some(&prompt_ir))
        .expect("capture must be persisted");

    assert!(!store.cipher_version().expect("cipher version").is_empty());
    assert_eq!(store.journal_mode().expect("journal mode"), "wal");
    assert_eq!(
        store.schema_version().expect("schema version"),
        SCHEMA_VERSION
    );
    assert_eq!(store.capture_count().expect("capture count"), 1);
    store.integrity_check().expect("database must be healthy");

    let stored = store
        .get_capture("capture_1")
        .expect("capture query must succeed")
        .expect("capture must exist");
    assert_eq!(stored.target_id, "openai");
    assert_eq!(stored.prompt_ir, Some(prompt_ir));
    assert!(
        serde_json::to_string(&stored.envelope)
            .expect("capture must encode")
            .contains(PROMPT_CANARY)
    );

    let results = store
        .search_captures("migration plan", 20)
        .expect("FTS query must succeed");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].capture_id, "capture_1");
    assert_eq!(results[0].model.as_deref(), Some("gpt-synthetic"));

    assert_files_do_not_contain(directory.path(), SECRET_CANARY.as_bytes());
    assert_files_do_not_contain(directory.path(), PROMPT_CANARY.as_bytes());
    let header = fs::read(&database_path).expect("database must be readable");
    assert!(!header.starts_with(b"SQLite format 3\0"));
}

#[test]
fn wrong_key_is_rejected_without_destroying_the_database() {
    let directory = tempdir().expect("temp directory must be created");
    let database_path = directory.path().join("captures.db");
    {
        let mut store = EncryptedStore::open(&database_path, DatabaseKey::from_bytes(KEY_BYTES))
            .expect("encrypted store must open");
        store
            .upsert_capture(&sanitized_capture("capture_1", 1, PROMPT_CANARY), None)
            .expect("capture must be persisted");
    }

    assert!(
        EncryptedStore::open(&database_path, DatabaseKey::from_bytes([0x24; 32])).is_err(),
        "a wrong key must never open an existing database"
    );
    let store = EncryptedStore::open(&database_path, DatabaseKey::from_bytes(KEY_BYTES))
        .expect("the original key must still work");
    assert_eq!(store.capture_count().expect("capture count"), 1);
}

#[test]
fn online_backup_restores_an_encrypted_searchable_database() {
    let directory = tempdir().expect("temp directory must be created");
    let database_path = directory.path().join("captures.db");
    let backup_path = directory.path().join("backups").join("captures.backup.db");
    let restored_path = directory.path().join("restored").join("captures.db");
    let mut store = EncryptedStore::open(&database_path, DatabaseKey::from_bytes(KEY_BYTES))
        .expect("encrypted store must open");
    store
        .upsert_capture(
            &sanitized_capture("capture_backup", 42, PROMPT_CANARY),
            None,
        )
        .expect("capture must be persisted");

    store
        .backup_to(&backup_path)
        .expect("online backup must succeed");
    assert_files_do_not_contain(
        backup_path.parent().expect("backup parent"),
        PROMPT_CANARY.as_bytes(),
    );
    drop(store);

    let restored = EncryptedStore::restore_from(
        &backup_path,
        &restored_path,
        DatabaseKey::from_bytes(KEY_BYTES),
    )
    .expect("backup must restore");
    assert_eq!(restored.capture_count().expect("capture count"), 1);
    assert_eq!(
        restored
            .search_captures("migration", 10)
            .expect("restored FTS must work")[0]
            .capture_id,
        "capture_backup"
    );
    restored.integrity_check().expect("restored DB is healthy");
    assert_files_do_not_contain(directory.path(), PROMPT_CANARY.as_bytes());
}

#[test]
fn cursor_pagination_and_delete_are_stable() {
    let directory = tempdir().expect("temp directory must be created");
    let mut store = EncryptedStore::open(
        directory.path().join("captures.db"),
        DatabaseKey::from_bytes(KEY_BYTES),
    )
    .expect("encrypted store must open");
    for (id, timestamp) in [("capture_1", 10), ("capture_2", 20), ("capture_3", 30)] {
        let capture = sanitized_capture(id, timestamp, id);
        store
            .upsert_capture(&capture, None)
            .expect("capture must be persisted");
    }

    let first = store.list_captures(2, None).expect("first page");
    assert_eq!(
        first
            .iter()
            .map(|capture| capture.capture_id.as_str())
            .collect::<Vec<_>>(),
        ["capture_3", "capture_2"]
    );
    let cursor = CaptureCursor {
        observed_at_unix_ms: first[1].observed_at_unix_ms,
        capture_id: first[1].capture_id.clone(),
    };
    let second = store.list_captures(2, Some(&cursor)).expect("second page");
    assert_eq!(second[0].capture_id, "capture_1");
    assert!(store.delete_capture("capture_2").expect("delete capture"));
    assert!(!store.delete_capture("missing").expect("delete missing"));
    assert_eq!(store.capture_count().expect("capture count"), 2);
}

fn assert_files_do_not_contain(directory: &Path, needle: &[u8]) {
    for entry in fs::read_dir(directory).expect("directory must be readable") {
        let entry = entry.expect("entry must be readable");
        let path = entry.path();
        if path.is_dir() {
            assert_files_do_not_contain(&path, needle);
            continue;
        }
        let bytes = fs::read(&path).expect("file must be readable");
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "plaintext canary found in {}",
            path.display()
        );
    }
}
