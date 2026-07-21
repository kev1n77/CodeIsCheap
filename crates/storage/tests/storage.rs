use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use codeischeap_capture_ipc::{
    CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureOutcome, CaptureSource, CapturedBody,
    CapturedBodyState, CapturedField, CapturedRequest, CapturedResponse, ResponseCompleteness,
};
use codeischeap_capture_policy::{CapturePolicy, SanitizedCapture};
use codeischeap_prompt_ir::{Evidence, MessageRole, PromptIr, PromptPart, ResponseTrace};
use codeischeap_storage::{
    CaptureCursor, CaptureWrite, DatabaseKey, DatabaseKeyStore, EncryptedStore, KeyStoreError,
    RetentionPolicy, SCHEMA_VERSION, StorageError, StorageOptions,
};
use tempfile::tempdir;

const KEY_BYTES: [u8; 32] = [0x42; 32];
const SECRET_CANARY: &str = "storage-secret-canary";
const PROMPT_CANARY: &str = "encrypted-prompt-canary migration plan";

struct ExistingRecoveryKeyStore;

impl DatabaseKeyStore for ExistingRecoveryKeyStore {
    fn load(&self) -> Result<DatabaseKey, KeyStoreError> {
        Ok(DatabaseKey::from_bytes(KEY_BYTES))
    }

    fn load_or_create(&self) -> Result<DatabaseKey, KeyStoreError> {
        panic!("read-only recovery must never create a database key")
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        Ok(())
    }
}

fn sanitized_capture(id: &str, observed_at: u64, prompt: &str) -> SanitizedCapture {
    let policy = CapturePolicy::load_default().expect("policy must load");
    let envelope = CaptureEnvelope {
        version: CAPTURE_ENVELOPE_VERSION.to_owned(),
        capture_id: id.to_owned(),
        observed_at_unix_ms: observed_at,
        source: CaptureSource::Mitmproxy,
        attribution: None,
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
        outcome: None,
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
fn response_outcomes_round_trip_into_queryable_encrypted_columns() {
    const RESPONSE_SECRET: &str = "response-storage-secret-canary";
    let directory = tempdir().expect("temp directory must be created");
    let database_path = directory.path().join("captures.db");
    let mut store = EncryptedStore::open(&database_path, DatabaseKey::from_bytes(KEY_BYTES))
        .expect("encrypted store must open");
    let policy = CapturePolicy::load_default().expect("policy must load");
    let mut envelope =
        sanitized_capture("capture_response", 50, "retry this request").into_envelope();
    envelope.outcome = Some(CaptureOutcome::Response(CapturedResponse {
        status: 429,
        headers: vec![CapturedField {
            name: "set-cookie".to_owned(),
            value: RESPONSE_SECRET.to_owned(),
        }],
        body: CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(serde_json::json!({
                "error": "rate limited",
                "token": RESPONSE_SECRET
            })),
        },
        duration_ms: 87,
        completeness: ResponseCompleteness::Complete,
    }));
    let capture = policy
        .sanitize_envelope(envelope)
        .expect("response must be sanitized");

    store
        .upsert_capture(&capture, None)
        .expect("response outcome must persist");

    let stored = store
        .get_capture("capture_response")
        .expect("capture query must succeed")
        .expect("capture must exist");
    let CaptureOutcome::Response(response) = stored
        .envelope
        .outcome
        .expect("response outcome must round trip")
    else {
        panic!("stored outcome must be a response");
    };
    assert_eq!(response.status, 429);
    assert_eq!(response.duration_ms, 87);
    assert!(response.headers.is_empty());
    assert_eq!(
        response.body.content,
        Some(serde_json::json!({"error": "rate limited"}))
    );
    let summary = store
        .list_captures(1, None)
        .expect("summary must load")
        .pop()
        .expect("summary must exist");
    assert_eq!(summary.outcome_kind.as_deref(), Some("response"));
    assert_eq!(summary.status_code, Some(429));
    assert_eq!(summary.duration_ms, Some(87));
    assert_files_do_not_contain(directory.path(), RESPONSE_SECRET.as_bytes());
}

#[test]
fn response_trace_does_not_pollute_prompt_full_text_search() {
    let directory = tempdir().expect("temp directory must be created");
    let mut store = EncryptedStore::open(
        directory.path().join("captures.db"),
        DatabaseKey::from_bytes(KEY_BYTES),
    )
    .expect("encrypted store must open");
    let capture = sanitized_capture("capture_search_scope", 51, "request-search-marker");
    let mut prompt = PromptIr::new("capture_search_scope", "openai");
    prompt.response = Some(ResponseTrace {
        id: Some("response_1".to_owned()),
        model: Some("gpt-test".to_owned()),
        role: MessageRole::Assistant,
        parts: vec![PromptPart::Text {
            id: "response_part_0".to_owned(),
            text: "response-only-marker".to_owned(),
            evidence: Evidence::unknown(),
        }],
        stop_reason: Some("stop".to_owned()),
        stop_sequence: None,
        usage: BTreeMap::new(),
        error: None,
        events: Vec::new(),
        evidence: Evidence::unknown(),
    });

    store
        .upsert_capture(&capture, Some(&prompt))
        .expect("capture must persist");

    assert_eq!(
        store
            .search_captures("request-search-marker", 10)
            .expect("request search must succeed")
            .len(),
        1
    );
    assert!(
        store
            .search_captures("response-only-marker", 10)
            .expect("response search must succeed")
            .is_empty()
    );
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
fn encrypted_backup_opens_read_only_and_rejects_every_store_mutation() {
    let directory = tempdir().expect("temp directory must be created");
    let database_path = directory.path().join("captures.db");
    let backup_path = directory.path().join("captures.pre-update.db");
    let mut writable = EncryptedStore::open(&database_path, DatabaseKey::from_bytes(KEY_BYTES))
        .expect("encrypted store must open");
    writable
        .upsert_capture(
            &sanitized_capture("recovery_capture", 42, "recovery marker"),
            None,
        )
        .expect("recovery fixture must persist");
    writable
        .backup_to(&backup_path)
        .expect("encrypted backup must succeed");
    drop(writable);

    let before = fs::read(&backup_path).expect("backup must be readable");
    let mut recovery =
        EncryptedStore::open_readonly_with_key_store(&backup_path, &ExistingRecoveryKeyStore)
            .expect("encrypted backup must open read-only with an existing key");

    assert!(recovery.is_read_only());
    assert_eq!(recovery.capture_count().expect("capture count"), 1);
    assert_eq!(
        recovery
            .search_captures("recovery marker", 10)
            .expect("read-only FTS must work")[0]
            .capture_id,
        "recovery_capture"
    );
    assert!(matches!(
        recovery.upsert_capture(
            &sanitized_capture("blocked_write", 43, "must not persist"),
            None,
        ),
        Err(StorageError::ReadOnly)
    ));
    assert!(matches!(
        recovery.delete_capture("recovery_capture"),
        Err(StorageError::ReadOnly)
    ));
    assert!(matches!(
        recovery.enforce_retention(&RetentionPolicy::default(), 100),
        Err(StorageError::ReadOnly)
    ));
    assert!(matches!(recovery.checkpoint(), Err(StorageError::ReadOnly)));
    assert!(matches!(
        recovery.backup_to(directory.path().join("blocked.db")),
        Err(StorageError::ReadOnly)
    ));
    drop(recovery);

    assert_eq!(
        fs::read(&backup_path).expect("backup must remain readable"),
        before,
        "read-only access must not alter the recovery backup"
    );
    assert!(!directory.path().join("blocked.db").exists());
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

#[test]
fn batch_writes_are_atomic_and_searchable() {
    let directory = tempdir().expect("temp directory must be created");
    let mut store = EncryptedStore::open(
        directory.path().join("captures.db"),
        DatabaseKey::from_bytes(KEY_BYTES),
    )
    .expect("encrypted store must open");
    let first = sanitized_capture("batch_1", 10, "alpha batch marker");
    let second = sanitized_capture("batch_2", 20, "beta batch marker");
    let mut first_prompt = PromptIr::new("batch_1", "openai");
    first_prompt.model = Some("gpt-batch".to_owned());

    assert_eq!(
        store
            .upsert_captures(&[
                CaptureWrite::new(&first, Some(&first_prompt)),
                CaptureWrite::new(&second, None),
            ])
            .expect("batch must persist"),
        2
    );
    assert_eq!(store.capture_count().expect("capture count"), 2);
    assert_eq!(
        store
            .search_captures("beta marker", 10)
            .expect("batch FTS must update")[0]
            .capture_id,
        "batch_2"
    );

    let invalid = sanitized_capture("batch_3", 30, "must roll back");
    let mismatched_prompt = PromptIr::new("different_request", "openai");
    let error = store
        .upsert_captures(&[
            CaptureWrite::new(&invalid, None),
            CaptureWrite::new(&second, Some(&mismatched_prompt)),
        ])
        .expect_err("invalid batch must fail before writing");
    assert!(matches!(error, StorageError::PromptRequestMismatch));
    assert!(
        store
            .get_capture("batch_3")
            .expect("capture query")
            .is_none()
    );
    assert_eq!(store.capture_count().expect("capture count"), 2);
}

#[test]
fn retention_removes_expired_and_excess_captures_in_bounded_transactions() {
    let directory = tempdir().expect("temp directory must be created");
    let mut store = EncryptedStore::open(
        directory.path().join("captures.db"),
        DatabaseKey::from_bytes(KEY_BYTES),
    )
    .expect("encrypted store must open");
    let captures = (1..=5)
        .map(|index| {
            sanitized_capture(
                &format!("retained_{index}"),
                index * 10,
                &format!("retention marker {index}"),
            )
        })
        .collect::<Vec<_>>();
    let writes = captures
        .iter()
        .map(|capture| CaptureWrite::new(capture, None))
        .collect::<Vec<_>>();
    store
        .upsert_captures(&writes)
        .expect("retention fixtures must persist");

    let report = store
        .enforce_retention(
            &RetentionPolicy {
                max_age: Some(std::time::Duration::from_millis(25)),
                max_captures: Some(2),
                batch_size: 1,
            },
            50,
        )
        .expect("retention must complete");

    assert_eq!(report.deleted_by_age, 2);
    assert_eq!(report.deleted_by_count, 1);
    assert_eq!(report.remaining_captures, 2);
    assert_eq!(report.transaction_count, 3);
    assert!(
        store
            .search_captures("marker 1", 10)
            .expect("expired FTS entries must be removed")
            .is_empty()
    );
    assert_eq!(
        store
            .list_captures(10, None)
            .expect("retained captures must list")
            .iter()
            .map(|capture| capture.capture_id.as_str())
            .collect::<Vec<_>>(),
        ["retained_5", "retained_4"]
    );
    store.integrity_check().expect("cleanup must preserve DB");
}

#[test]
fn disk_pressure_rejects_writes_without_damaging_the_database() {
    let directory = tempdir().expect("temp directory must be created");
    let mut store = EncryptedStore::open_with_options(
        directory.path().join("captures.db"),
        DatabaseKey::from_bytes(KEY_BYTES),
        StorageOptions {
            minimum_free_space_bytes: u64::MAX,
        },
    )
    .expect("encrypted store must open before pressure guard");

    let error = store
        .upsert_capture(
            &sanitized_capture("pressure_1", 1, "must not persist"),
            None,
        )
        .expect_err("pressure guard must reject the write");
    assert!(error.is_disk_pressure());
    assert!(matches!(error, StorageError::DiskPressure { .. }));
    assert_eq!(store.capture_count().expect("capture count"), 0);
    store
        .integrity_check()
        .expect("pressure rejection must preserve DB");
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
