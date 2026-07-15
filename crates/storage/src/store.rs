use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use codeischeap_capture_ipc::{CaptureEnvelope, CaptureOutcome, CaptureSource};
use codeischeap_capture_policy::{CAPTURE_POLICY_VERSION, SanitizedCapture};
use codeischeap_prompt_ir::{PromptIr, Validate};
use rusqlite::backup::Backup;
use rusqlite::types::Type;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::StorageError;
use crate::key::{DatabaseKey, DatabaseKeyStore};
use crate::migrations::{migrate, validate_schema};
use crate::model::{
    CaptureCursor, CaptureSummary, CaptureWrite, RetentionPolicy, RetentionReport, StorageOptions,
    StoredCapture,
};

pub const MAX_PAGE_SIZE: usize = 200;
const MAX_RETENTION_BATCH_SIZE: usize = 10_000;

pub struct EncryptedStore {
    connection: Connection,
    key: DatabaseKey,
    path: PathBuf,
    options: StorageOptions,
}

impl EncryptedStore {
    pub fn open(path: impl AsRef<Path>, key: DatabaseKey) -> Result<Self, StorageError> {
        Self::open_with_options(path, key, StorageOptions::default())
    }

    pub fn open_with_options(
        path: impl AsRef<Path>,
        key: DatabaseKey,
        options: StorageOptions,
    ) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        prepare_parent(&path)?;
        let mut connection = open_writable_connection(&path, &key)?;
        migrate(&mut connection)?;
        set_private_file_permissions(&path)?;
        Ok(Self {
            connection,
            key,
            path,
            options,
        })
    }

    pub fn open_with_key_store(
        path: impl AsRef<Path>,
        key_store: &impl DatabaseKeyStore,
    ) -> Result<Self, StorageError> {
        Self::open_with_key_store_and_options(path, key_store, StorageOptions::default())
    }

    pub fn open_with_key_store_and_options(
        path: impl AsRef<Path>,
        key_store: &impl DatabaseKeyStore,
        options: StorageOptions,
    ) -> Result<Self, StorageError> {
        let key = key_store.load_or_create()?;
        Self::open_with_options(path, key, options)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn cipher_version(&self) -> Result<String, StorageError> {
        cipher_version(&self.connection)
    }

    pub fn journal_mode(&self) -> Result<String, StorageError> {
        self.connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn schema_version(&self) -> Result<i32, StorageError> {
        self.connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(Into::into)
    }

    pub fn integrity_check(&self) -> Result<(), StorageError> {
        integrity_check(&self.connection)
    }

    pub fn upsert_capture(
        &mut self,
        capture: &SanitizedCapture,
        prompt_ir: Option<&PromptIr>,
    ) -> Result<(), StorageError> {
        self.upsert_captures(&[CaptureWrite::new(capture, prompt_ir)])?;
        Ok(())
    }

    pub fn upsert_captures(&mut self, writes: &[CaptureWrite<'_>]) -> Result<usize, StorageError> {
        if writes.is_empty() {
            return Ok(0);
        }
        let prepared = writes
            .iter()
            .map(prepare_capture)
            .collect::<Result<Vec<_>, _>>()?;
        self.ensure_disk_headroom()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for capture in &prepared {
            upsert_prepared(&transaction, capture)?;
        }
        transaction.commit()?;
        Ok(prepared.len())
    }

    pub fn available_space_bytes(&self) -> Result<u64, StorageError> {
        let parent = self
            .path
            .parent()
            .ok_or(StorageError::InvalidBackupTarget)?;
        fs2::available_space(parent).map_err(Into::into)
    }

    pub fn ensure_disk_headroom(&self) -> Result<u64, StorageError> {
        let available_bytes = self.available_space_bytes()?;
        if available_bytes < self.options.minimum_free_space_bytes {
            return Err(StorageError::DiskPressure {
                available_bytes,
                required_bytes: self.options.minimum_free_space_bytes,
            });
        }
        Ok(available_bytes)
    }

    pub fn get_capture(&self, capture_id: &str) -> Result<Option<StoredCapture>, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT target_id, request_json, prompt_ir_json FROM captures WHERE capture_id = ?1",
                [capture_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?;

        row.map(|(target_id, request_json, prompt_ir_json)| {
            Ok(StoredCapture {
                target_id,
                envelope: serde_json::from_str(&request_json)?,
                prompt_ir: prompt_ir_json
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()?,
            })
        })
        .transpose()
    }

    pub fn list_captures(
        &self,
        limit: usize,
        cursor: Option<&CaptureCursor>,
    ) -> Result<Vec<CaptureSummary>, StorageError> {
        let limit = checked_limit(limit)?;
        let mut summaries = Vec::new();
        if let Some(cursor) = cursor {
            let observed_at = i64::try_from(cursor.observed_at_unix_ms)
                .map_err(|_| StorageError::InvalidPageLimit)?;
            let mut statement = self.connection.prepare(
                "
                SELECT capture_id, observed_at_unix_ms, target_id, provider_id, model,
                       method, host, path, prompt_ir_json IS NOT NULL, redaction_count,
                       outcome_kind, status_code, duration_ms
                FROM captures
                WHERE observed_at_unix_ms < ?1
                   OR (observed_at_unix_ms = ?1 AND capture_id < ?2)
                ORDER BY observed_at_unix_ms DESC, capture_id DESC
                LIMIT ?3
                ",
            )?;
            let rows = statement.query_map(
                params![observed_at, cursor.capture_id, limit],
                row_to_summary,
            )?;
            for row in rows {
                summaries.push(row?);
            }
        } else {
            let mut statement = self.connection.prepare(
                "
                SELECT capture_id, observed_at_unix_ms, target_id, provider_id, model,
                       method, host, path, prompt_ir_json IS NOT NULL, redaction_count,
                       outcome_kind, status_code, duration_ms
                FROM captures
                ORDER BY observed_at_unix_ms DESC, capture_id DESC
                LIMIT ?1
                ",
            )?;
            let rows = statement.query_map([limit], row_to_summary)?;
            for row in rows {
                summaries.push(row?);
            }
        }
        Ok(summaries)
    }

    pub fn search_captures(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<CaptureSummary>, StorageError> {
        let query = plain_fts_query(query)?;
        let limit = checked_limit(limit)?;
        let mut statement = self.connection.prepare(
            "
            SELECT c.capture_id, c.observed_at_unix_ms, c.target_id, c.provider_id, c.model,
                   c.method, c.host, c.path, c.prompt_ir_json IS NOT NULL, c.redaction_count,
                   c.outcome_kind, c.status_code, c.duration_ms
            FROM capture_search
            JOIN captures c ON c.capture_id = capture_search.capture_id
            WHERE capture_search MATCH ?1
            ORDER BY bm25(capture_search), c.observed_at_unix_ms DESC
            LIMIT ?2
            ",
        )?;
        let rows = statement.query_map(params![query, limit], row_to_summary)?;
        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(row?);
        }
        Ok(summaries)
    }

    pub fn delete_capture(&mut self, capture_id: &str) -> Result<bool, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM capture_search WHERE capture_id = ?1",
            [capture_id],
        )?;
        let deleted =
            transaction.execute("DELETE FROM captures WHERE capture_id = ?1", [capture_id])?;
        transaction.commit()?;
        Ok(deleted != 0)
    }

    pub fn capture_count(&self) -> Result<u64, StorageError> {
        let count: i64 = self
            .connection
            .query_row("SELECT count(*) FROM captures", [], |row| row.get(0))
            .map_err(StorageError::from)?;
        u64::try_from(count).map_err(|_| StorageError::NumericOutOfRange)
    }

    pub fn enforce_retention(
        &mut self,
        policy: &RetentionPolicy,
        now_unix_ms: u64,
    ) -> Result<RetentionReport, StorageError> {
        validate_retention_policy(policy)?;
        let mut report = RetentionReport {
            deleted_by_age: 0,
            deleted_by_count: 0,
            remaining_captures: self.capture_count()?,
            transaction_count: 0,
        };

        if let Some(max_age) = policy.max_age {
            let max_age_ms = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
            let cutoff = now_unix_ms.saturating_sub(max_age_ms);
            let cutoff = i64::try_from(cutoff).map_err(|_| StorageError::NumericOutOfRange)?;
            loop {
                let ids = select_oldest_before(&self.connection, cutoff, policy.batch_size)?;
                if ids.is_empty() {
                    break;
                }
                let deleted = delete_capture_ids(&mut self.connection, &ids)?;
                report.deleted_by_age += deleted;
                report.transaction_count += 1;
            }
        }

        if let Some(max_captures) = policy.max_captures {
            loop {
                let count = self.capture_count()?;
                let excess = count.saturating_sub(max_captures);
                if excess == 0 {
                    break;
                }
                let limit = usize::try_from(excess.min(policy.batch_size as u64))
                    .map_err(|_| StorageError::NumericOutOfRange)?;
                let ids = select_oldest(&self.connection, limit)?;
                let deleted = delete_capture_ids(&mut self.connection, &ids)?;
                report.deleted_by_count += deleted;
                report.transaction_count += 1;
            }
        }

        report.remaining_captures = self.capture_count()?;
        if report.deleted_by_age + report.deleted_by_count > 0 {
            self.checkpoint()?;
        }
        Ok(report)
    }

    pub fn checkpoint(&self) -> Result<(), StorageError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    pub fn backup_to(&self, path: impl AsRef<Path>) -> Result<(), StorageError> {
        let path = path.as_ref();
        if path == self.path {
            return Err(StorageError::InvalidBackupTarget);
        }
        prepare_parent(path)?;
        remove_database_family(path)?;
        let mut destination = open_writable_connection(path, &self.key)?;
        {
            let backup = Backup::new(&self.connection, &mut destination)?;
            backup.run_to_completion(128, Duration::from_millis(5), None)?;
        }
        validate_schema(&destination)?;
        integrity_check(&destination)?;
        destination.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        set_private_file_permissions(path)?;
        Ok(())
    }

    pub fn restore_from(
        backup_path: impl AsRef<Path>,
        destination_path: impl AsRef<Path>,
        key: DatabaseKey,
    ) -> Result<Self, StorageError> {
        let backup_path = backup_path.as_ref();
        let destination_path = destination_path.as_ref().to_path_buf();
        if backup_path == destination_path {
            return Err(StorageError::InvalidBackupTarget);
        }
        let source = open_readonly_connection(backup_path, &key)?;
        validate_schema(&source)?;
        integrity_check(&source)?;
        prepare_parent(&destination_path)?;
        remove_database_family(&destination_path)?;
        let mut destination = open_writable_connection(&destination_path, &key)?;
        {
            let backup = Backup::new(&source, &mut destination)?;
            backup.run_to_completion(128, Duration::from_millis(5), None)?;
        }
        validate_schema(&destination)?;
        integrity_check(&destination)?;
        destination.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        set_private_file_permissions(&destination_path)?;
        Ok(Self {
            connection: destination,
            key,
            path: destination_path,
            options: StorageOptions::default(),
        })
    }
}

struct PreparedCapture {
    capture_id: String,
    observed_at: i64,
    target_id: String,
    source: &'static str,
    method: String,
    scheme: String,
    host: String,
    port: i64,
    path: String,
    provider_id: Option<String>,
    model: Option<String>,
    operation: Option<String>,
    request_json: String,
    prompt_ir_json: Option<String>,
    redaction_count: i64,
    outcome: OutcomeColumns,
    searchable_text: String,
}

fn prepare_capture(write: &CaptureWrite<'_>) -> Result<PreparedCapture, StorageError> {
    if let Some(prompt_ir) = write.prompt_ir {
        prompt_ir.validate()?;
        if prompt_ir.request_id != write.capture.envelope().capture_id {
            return Err(StorageError::PromptRequestMismatch);
        }
    }

    let envelope = write.capture.envelope();
    Ok(PreparedCapture {
        capture_id: envelope.capture_id.clone(),
        observed_at: i64::try_from(envelope.observed_at_unix_ms)
            .map_err(|_| StorageError::NumericOutOfRange)?,
        target_id: write.capture.target_id().to_owned(),
        source: source_name(envelope.source),
        method: envelope.request.method.clone(),
        scheme: envelope.request.scheme.clone(),
        host: envelope.request.host.clone(),
        port: i64::from(envelope.request.port),
        path: envelope.request.path.clone(),
        provider_id: write.prompt_ir.map(|prompt| prompt.provider.id.clone()),
        model: write.prompt_ir.and_then(|prompt| prompt.model.clone()),
        operation: write.prompt_ir.and_then(|prompt| prompt.operation.clone()),
        request_json: serde_json::to_string(envelope)?,
        prompt_ir_json: write.prompt_ir.map(serde_json::to_string).transpose()?,
        redaction_count: i64::try_from(envelope.redactions.len())
            .map_err(|_| StorageError::NumericOutOfRange)?,
        outcome: outcome_columns(envelope)?,
        searchable_text: searchable_text(envelope, write.prompt_ir)?,
    })
}

fn upsert_prepared(
    transaction: &rusqlite::Transaction<'_>,
    capture: &PreparedCapture,
) -> Result<(), StorageError> {
    transaction.execute(
        "
        INSERT INTO captures (
            capture_id, observed_at_unix_ms, target_id, source, method, scheme,
            host, port, path, provider_id, model, operation, request_json,
            prompt_ir_json, redaction_count, policy_version, outcome_kind,
            status_code, duration_ms
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
            ?17, ?18, ?19
        )
        ON CONFLICT(capture_id) DO UPDATE SET
            observed_at_unix_ms = excluded.observed_at_unix_ms,
            target_id = excluded.target_id,
            source = excluded.source,
            method = excluded.method,
            scheme = excluded.scheme,
            host = excluded.host,
            port = excluded.port,
            path = excluded.path,
            provider_id = excluded.provider_id,
            model = excluded.model,
            operation = excluded.operation,
            request_json = excluded.request_json,
            prompt_ir_json = excluded.prompt_ir_json,
            redaction_count = excluded.redaction_count,
            policy_version = excluded.policy_version,
            outcome_kind = excluded.outcome_kind,
            status_code = excluded.status_code,
            duration_ms = excluded.duration_ms
        ",
        params![
            capture.capture_id.as_str(),
            capture.observed_at,
            capture.target_id.as_str(),
            capture.source,
            capture.method.as_str(),
            capture.scheme.as_str(),
            capture.host.as_str(),
            capture.port,
            capture.path.as_str(),
            capture.provider_id.as_deref(),
            capture.model.as_deref(),
            capture.operation.as_deref(),
            capture.request_json.as_str(),
            capture.prompt_ir_json.as_deref(),
            capture.redaction_count,
            CAPTURE_POLICY_VERSION,
            capture.outcome.kind,
            capture.outcome.status_code,
            capture.outcome.duration_ms,
        ],
    )?;
    transaction.execute(
        "DELETE FROM capture_search WHERE capture_id = ?1",
        [capture.capture_id.as_str()],
    )?;
    transaction.execute(
        "INSERT INTO capture_search (capture_id, searchable_text) VALUES (?1, ?2)",
        params![
            capture.capture_id.as_str(),
            capture.searchable_text.as_str()
        ],
    )?;
    Ok(())
}

fn validate_retention_policy(policy: &RetentionPolicy) -> Result<(), StorageError> {
    if !(1..=MAX_RETENTION_BATCH_SIZE).contains(&policy.batch_size) {
        return Err(StorageError::InvalidRetentionPolicy);
    }
    Ok(())
}

fn select_oldest_before(
    connection: &Connection,
    cutoff_unix_ms: i64,
    limit: usize,
) -> Result<Vec<String>, StorageError> {
    let limit = i64::try_from(limit).map_err(|_| StorageError::InvalidRetentionPolicy)?;
    let mut statement = connection.prepare(
        "
        SELECT capture_id
        FROM captures
        WHERE observed_at_unix_ms < ?1
        ORDER BY observed_at_unix_ms ASC, capture_id ASC
        LIMIT ?2
        ",
    )?;
    statement
        .query_map(params![cutoff_unix_ms, limit], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn select_oldest(connection: &Connection, limit: usize) -> Result<Vec<String>, StorageError> {
    let limit = i64::try_from(limit).map_err(|_| StorageError::InvalidRetentionPolicy)?;
    let mut statement = connection.prepare(
        "
        SELECT capture_id
        FROM captures
        ORDER BY observed_at_unix_ms ASC, capture_id ASC
        LIMIT ?1
        ",
    )?;
    statement
        .query_map([limit], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn delete_capture_ids(
    connection: &mut Connection,
    capture_ids: &[String],
) -> Result<u64, StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut deleted = 0_u64;
    for capture_id in capture_ids {
        transaction.execute(
            "DELETE FROM capture_search WHERE capture_id = ?1",
            [capture_id],
        )?;
        deleted += u64::try_from(
            transaction.execute("DELETE FROM captures WHERE capture_id = ?1", [capture_id])?,
        )
        .map_err(|_| StorageError::NumericOutOfRange)?;
    }
    transaction.commit()?;
    Ok(deleted)
}

fn open_writable_connection(path: &Path, key: &DatabaseKey) -> Result<Connection, StorageError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )?;
    configure_encrypted_connection(&connection, key, true)?;
    Ok(connection)
}

fn open_readonly_connection(path: &Path, key: &DatabaseKey) -> Result<Connection, StorageError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )?;
    configure_encrypted_connection(&connection, key, false)?;
    Ok(connection)
}

fn configure_encrypted_connection(
    connection: &Connection,
    key: &DatabaseKey,
    writable: bool,
) -> Result<(), StorageError> {
    connection.execute_batch(&format!(
        "PRAGMA key = \"x'{}'\";",
        encode_hex(key.expose())
    ))?;
    if cipher_version(connection)?.trim().is_empty() {
        return Err(StorageError::CipherUnavailable);
    }
    connection.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "
        PRAGMA foreign_keys = ON;
        PRAGMA temp_store = MEMORY;
        PRAGMA secure_delete = ON;
        PRAGMA cache_size = -8192;
        ",
    )?;
    // SQLCipher's locked allocator can overflow on Windows when VirtualLock is denied.
    #[cfg(not(target_os = "windows"))]
    connection.execute_batch("PRAGMA cipher_memory_security = ON;")?;
    if writable {
        let mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StorageError::UnexpectedJournalMode(mode));
        }
        connection.execute_batch(
            "
            PRAGMA synchronous = FULL;
            PRAGMA wal_autocheckpoint = 1000;
            PRAGMA journal_size_limit = 67108864;
            ",
        )?;
    } else {
        connection.execute_batch("PRAGMA query_only = ON;")?;
    }
    Ok(())
}

fn cipher_version(connection: &Connection) -> Result<String, StorageError> {
    connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .optional()?
        .ok_or(StorageError::CipherUnavailable)
}

fn integrity_check(connection: &Connection) -> Result<(), StorageError> {
    let result: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(StorageError::IntegrityCheckFailed(result))
    }
}

fn checked_limit(limit: usize) -> Result<i64, StorageError> {
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(StorageError::InvalidPageLimit);
    }
    i64::try_from(limit).map_err(|_| StorageError::InvalidPageLimit)
}

fn plain_fts_query(query: &str) -> Result<String, StorageError> {
    let terms: Vec<String> = query
        .split_whitespace()
        .filter(|term| !term.is_empty())
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect();
    if terms.is_empty() {
        return Err(StorageError::EmptySearch);
    }
    Ok(terms.join(" AND "))
}

fn row_to_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<CaptureSummary> {
    let observed_at: i64 = row.get(1)?;
    let redaction_count: i64 = row.get(9)?;
    let status_code: Option<i64> = row.get(11)?;
    let duration_ms: Option<i64> = row.get(12)?;
    Ok(CaptureSummary {
        capture_id: row.get(0)?,
        observed_at_unix_ms: u64::try_from(observed_at).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(1, Type::Integer, Box::new(error))
        })?,
        target_id: row.get(2)?,
        provider_id: row.get(3)?,
        model: row.get(4)?,
        method: row.get(5)?,
        host: row.get(6)?,
        path: row.get(7)?,
        has_prompt_ir: row.get(8)?,
        redaction_count: usize::try_from(redaction_count).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(9, Type::Integer, Box::new(error))
        })?,
        outcome_kind: row.get(10)?,
        status_code: status_code
            .map(u16::try_from)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(11, Type::Integer, Box::new(error))
            })?,
        duration_ms: duration_ms
            .map(u64::try_from)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(12, Type::Integer, Box::new(error))
            })?,
    })
}

struct OutcomeColumns {
    kind: Option<&'static str>,
    status_code: Option<i64>,
    duration_ms: Option<i64>,
}

fn outcome_columns(envelope: &CaptureEnvelope) -> Result<OutcomeColumns, StorageError> {
    match envelope.outcome.as_ref() {
        None => Ok(OutcomeColumns {
            kind: None,
            status_code: None,
            duration_ms: None,
        }),
        Some(CaptureOutcome::Response(response)) => Ok(OutcomeColumns {
            kind: Some("response"),
            status_code: Some(i64::from(response.status)),
            duration_ms: Some(
                i64::try_from(response.duration_ms).map_err(|_| StorageError::NumericOutOfRange)?,
            ),
        }),
        Some(CaptureOutcome::UpstreamFailure(failure)) => Ok(OutcomeColumns {
            kind: Some("upstream_failure"),
            status_code: None,
            duration_ms: Some(
                i64::try_from(failure.duration_ms).map_err(|_| StorageError::NumericOutOfRange)?,
            ),
        }),
    }
}

fn searchable_text(
    envelope: &CaptureEnvelope,
    prompt_ir: Option<&PromptIr>,
) -> Result<String, StorageError> {
    let mut values = vec![envelope.request.host.clone(), envelope.request.path.clone()];
    if let Some(content) = &envelope.request.body.content {
        collect_json_strings(content, &mut values);
    }
    if let Some(prompt_ir) = prompt_ir {
        values.push(prompt_ir.provider.id.clone());
        if let Some(model) = &prompt_ir.model {
            values.push(model.clone());
        }
        let mut searchable_prompt = prompt_ir.clone();
        searchable_prompt.response = None;
        collect_json_strings(&serde_json::to_value(searchable_prompt)?, &mut values);
    }
    Ok(values.join(" "))
}

fn collect_json_strings(value: &serde_json::Value, output: &mut Vec<String>) {
    match value {
        serde_json::Value::String(value) => output.push(value.clone()),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_strings(value, output);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_json_strings(value, output);
            }
        }
        _ => {}
    }
}

fn source_name(source: CaptureSource) -> &'static str {
    match source {
        CaptureSource::Gateway => "gateway",
        CaptureSource::Mitmproxy => "mitmproxy",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn prepare_parent(path: &Path) -> Result<(), StorageError> {
    let parent = path.parent().ok_or(StorageError::InvalidBackupTarget)?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn remove_database_family(path: &Path) -> Result<(), StorageError> {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(StorageError::Io(error)),
        }
    }
    Ok(())
}
