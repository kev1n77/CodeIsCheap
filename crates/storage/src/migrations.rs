use rusqlite::{Connection, TransactionBehavior};

use crate::StorageError;

pub const SCHEMA_VERSION: i32 = 2;

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), StorageError> {
    let mut version = schema_version(connection)?;
    if version > SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion(version));
    }
    while version < SCHEMA_VERSION {
        match version {
            0 => migrate_v1(connection)?,
            1 => migrate_v2(connection)?,
            _ => return Err(StorageError::UnsupportedSchemaVersion(version)),
        }
        version = schema_version(connection)?;
    }
    Ok(())
}

fn migrate_v1(connection: &mut Connection) -> Result<(), StorageError> {
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
    transaction.pragma_update(None, "user_version", 1)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v2(connection: &mut Connection) -> Result<(), StorageError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "
        ALTER TABLE captures ADD COLUMN outcome_kind TEXT
            CHECK (outcome_kind IN ('response', 'upstream_failure'));
        ALTER TABLE captures ADD COLUMN status_code INTEGER
            CHECK (status_code BETWEEN 100 AND 599);
        ALTER TABLE captures ADD COLUMN duration_ms INTEGER
            CHECK (duration_ms >= 0);
        CREATE INDEX captures_outcome_idx
            ON captures (outcome_kind, observed_at_unix_ms DESC);
        INSERT INTO schema_migrations (version, applied_at_unix_s)
        VALUES (2, unixepoch());
        ",
    )?;
    transaction.pragma_update(None, "user_version", 2)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_databases_apply_every_migration() {
        let mut connection = Connection::open_in_memory().expect("database must open");

        migrate(&mut connection).expect("all migrations must apply");

        assert_eq!(schema_version(&connection).expect("version must load"), 2);
        assert!(capture_columns(&connection).contains(&"outcome_kind".to_owned()));
        assert_eq!(migration_versions(&connection), vec![1, 2]);
    }

    #[test]
    fn version_one_databases_upgrade_without_losing_captures() {
        let mut connection = Connection::open_in_memory().expect("database must open");
        migrate_v1(&mut connection).expect("v1 must apply");
        connection
            .execute(
                "INSERT INTO captures (
                    capture_id, observed_at_unix_ms, target_id, source, method, scheme,
                    host, port, path, request_json, redaction_count, policy_version
                 ) VALUES ('legacy', 1, 'openai', 'gateway', 'POST', 'https',
                    'api.openai.com', 443, '/v1/responses', '{}', 0, '0.1')",
                [],
            )
            .expect("legacy capture must insert");

        migrate(&mut connection).expect("v1 database must upgrade");

        assert_eq!(schema_version(&connection).expect("version must load"), 2);
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM captures", [], |row| row
                    .get::<_, i64>(0))
                .expect("capture count must load"),
            1
        );
        assert_eq!(migration_versions(&connection), vec![1, 2]);
    }

    fn capture_columns(connection: &Connection) -> Vec<String> {
        let mut statement = connection
            .prepare("SELECT name FROM pragma_table_info('captures') ORDER BY cid")
            .expect("column query must prepare");
        statement
            .query_map([], |row| row.get(0))
            .expect("columns must query")
            .collect::<Result<Vec<_>, _>>()
            .expect("columns must load")
    }

    fn migration_versions(connection: &Connection) -> Vec<i64> {
        let mut statement = connection
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .expect("migration query must prepare");
        statement
            .query_map([], |row| row.get(0))
            .expect("migrations must query")
            .collect::<Result<Vec<_>, _>>()
            .expect("migrations must load")
    }
}
