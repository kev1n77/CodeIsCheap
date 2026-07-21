//! SQLCipher-backed persistence for sanitized CodeIsCheap captures.

mod key;
mod migrations;
mod model;
mod store;

use std::fmt;
use std::io;

use codeischeap_prompt_ir::ValidationErrors;

pub use key::{DATABASE_KEY_BYTES, DatabaseKey, DatabaseKeyStore, KeyStoreError, OsKeyStore};
pub use migrations::SCHEMA_VERSION;
pub use model::{
    CaptureCursor, CaptureSummary, CaptureWrite, DEFAULT_MAX_CAPTURE_AGE, DEFAULT_MAX_CAPTURES,
    DEFAULT_MINIMUM_FREE_SPACE_BYTES, DEFAULT_RETENTION_BATCH_SIZE, RetentionPolicy,
    RetentionReport, StorageOptions, StoredCapture,
};
pub use store::{EncryptedStore, MAX_PAGE_SIZE};

#[derive(Debug)]
pub enum StorageError {
    Io(io::Error),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    PromptIr(ValidationErrors),
    KeyStore(KeyStoreError),
    CipherUnavailable,
    UnexpectedJournalMode(String),
    UnsupportedSchemaVersion(i32),
    PromptRequestMismatch,
    NumericOutOfRange,
    InvalidPageLimit,
    EmptySearch,
    InvalidBackupTarget,
    ReadOnly,
    InvalidRetentionPolicy,
    DiskPressure {
        available_bytes: u64,
        required_bytes: u64,
    },
    DiskFull,
    IntegrityCheckFailed(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "storage I/O failed: {error}"),
            Self::Sqlite(error) => {
                write!(formatter, "encrypted database operation failed: {error}")
            }
            Self::Json(error) => write!(formatter, "stored JSON is invalid: {error}"),
            Self::PromptIr(error) => write!(formatter, "{error}"),
            Self::KeyStore(error) => write!(formatter, "database key operation failed: {error}"),
            Self::CipherUnavailable => write!(formatter, "SQLCipher support is unavailable"),
            Self::UnexpectedJournalMode(mode) => {
                write!(formatter, "encrypted database refused WAL mode: {mode}")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "database schema version {version} is unsupported"
                )
            }
            Self::PromptRequestMismatch => {
                write!(formatter, "Prompt IR request id does not match its capture")
            }
            Self::NumericOutOfRange => write!(formatter, "storage numeric value is out of range"),
            Self::InvalidPageLimit => write!(formatter, "capture page limit is invalid"),
            Self::EmptySearch => write!(formatter, "capture search query is empty"),
            Self::InvalidBackupTarget => write!(formatter, "database backup target is invalid"),
            Self::ReadOnly => write!(
                formatter,
                "encrypted workspace is open in read-only recovery mode"
            ),
            Self::InvalidRetentionPolicy => {
                write!(formatter, "capture retention policy is invalid")
            }
            Self::DiskPressure {
                available_bytes,
                required_bytes,
            } => write!(
                formatter,
                "capture storage paused: {available_bytes} bytes available, {required_bytes} bytes required"
            ),
            Self::DiskFull => write!(formatter, "capture storage paused because the disk is full"),
            Self::IntegrityCheckFailed(result) => {
                write!(
                    formatter,
                    "encrypted database integrity check failed: {result}"
                )
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::PromptIr(error) => Some(error),
            Self::KeyStore(error) => Some(error),
            _ => None,
        }
    }
}

impl StorageError {
    #[must_use]
    pub const fn is_disk_pressure(&self) -> bool {
        matches!(self, Self::DiskPressure { .. } | Self::DiskFull)
    }
}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        if matches!(
            &error,
            rusqlite::Error::SqliteFailure(inner, _)
                if inner.code == rusqlite::ErrorCode::DiskFull
        ) {
            Self::DiskFull
        } else {
            Self::Sqlite(error)
        }
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<ValidationErrors> for StorageError {
    fn from(error: ValidationErrors) -> Self {
        Self::PromptIr(error)
    }
}

impl From<KeyStoreError> for StorageError {
    fn from(error: KeyStoreError) -> Self {
        Self::KeyStore(error)
    }
}
