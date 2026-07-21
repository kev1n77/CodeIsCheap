use std::time::Duration;

use codeischeap_capture_ipc::CaptureEnvelope;
use codeischeap_capture_policy::SanitizedCapture;
use codeischeap_prompt_ir::PromptIr;

pub const DEFAULT_MINIMUM_FREE_SPACE_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_MAX_CAPTURE_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const DEFAULT_MAX_CAPTURES: u64 = 50_000;
pub const DEFAULT_RETENTION_BATCH_SIZE: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageOptions {
    pub minimum_free_space_bytes: u64,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            minimum_free_space_bytes: DEFAULT_MINIMUM_FREE_SPACE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub max_age: Option<Duration>,
    pub max_captures: Option<u64>,
    pub batch_size: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age: Some(DEFAULT_MAX_CAPTURE_AGE),
            max_captures: Some(DEFAULT_MAX_CAPTURES),
            batch_size: DEFAULT_RETENTION_BATCH_SIZE,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CaptureWrite<'a> {
    pub capture: &'a SanitizedCapture,
    pub prompt_ir: Option<&'a PromptIr>,
}

impl<'a> CaptureWrite<'a> {
    #[must_use]
    pub const fn new(capture: &'a SanitizedCapture, prompt_ir: Option<&'a PromptIr>) -> Self {
        Self { capture, prompt_ir }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionReport {
    pub deleted_by_age: u64,
    pub deleted_by_count: u64,
    pub remaining_captures: u64,
    pub transaction_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureCursor {
    pub observed_at_unix_ms: u64,
    pub capture_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSummary {
    pub capture_id: String,
    pub observed_at_unix_ms: u64,
    pub target_id: String,
    pub provider_id: Option<String>,
    pub model: Option<String>,
    pub method: String,
    pub host: String,
    pub path: String,
    pub has_prompt_ir: bool,
    pub redaction_count: usize,
    pub outcome_kind: Option<String>,
    pub status_code: Option<u16>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureMetrics {
    pub earliest_capture_at_unix_ms: Option<u64>,
    pub supported_capture_count: u64,
    pub parsed_capture_count: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredCapture {
    pub target_id: String,
    pub envelope: CaptureEnvelope,
    pub prompt_ir: Option<PromptIr>,
}
