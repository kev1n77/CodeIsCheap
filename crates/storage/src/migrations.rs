use rusqlite::{Connection, TransactionBehavior};

use crate::StorageError;

pub const SCHEMA_VERSION: i32 = 1;

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), StorageError> {
    let version = schema_version(connection)?;
    if version > SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion(version));
    }
    if version == SCHEMA_VERSION {
        return Ok(());
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let statements = [
        "
        CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at_unix_s INTEGER NOT NULL
        ) STRICT;
        ",
        "
        CREATE TABLE captures (
            capture_id TEXT PRIMARY KEY,
            observed_at_unix_ms INTEGER NOT NULL CHECK (observed_at_unix_ms >= 0),
            target_id TEXT NOT NULL,
            source TEXT NOT NULL,
            method TEXT NOT NULL,
            scheme TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
            path TEXT NOT NULL,
            provider_id TEXT,
            model TEXT,
            operation TEXT,
            request_json TEXT NOT NULL,
            prompt_ir_json TEXT,
            redaction_count INTEGER NOT NULL CHECK (redaction_count >= 0),
            policy_version TEXT NOT NULL
        ) STRICT;
        ",
        "
        CREATE INDEX captures_observed_idx
            ON captures (observed_at_unix_ms DESC, capture_id DESC);
        ",
        "
        CREATE INDEX captures_provider_idx
            ON captures (provider_id, observed_at_unix_ms DESC);
        ",
        "
        CREATE INDEX captures_target_idx
            ON captures (target_id, observed_at_unix_ms DESC);
        ",
        "
        CREATE VIRTUAL TABLE capture_search USING fts5(
            capture_id UNINDEXED,
            searchable_text,
            tokenize = 'unicode61'
        );
        ",
        "
        INSERT INTO schema_migrations (version, applied_at_unix_s)
        VALUES (1, unixepoch());
        ",
    ];
    for statement in statements {
        transaction.execute_batch(statement)?;
    }
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), StorageError> {
    let version = schema_version(connection)?;
    if version != SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion(version));
    }
    Ok(())
}

fn schema_version(connection: &Connection) -> Result<i32, rusqlite::Error> {
    connection.pragma_query_value(None, "user_version", |row| row.get(0))
}
