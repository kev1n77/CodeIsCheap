use codeischeap_capture_ipc::CaptureEnvelope;
use codeischeap_prompt_ir::PromptIr;

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

#[derive(Debug, Clone, PartialEq)]
pub struct StoredCapture {
    pub target_id: String,
    pub envelope: CaptureEnvelope,
    pub prompt_ir: Option<PromptIr>,
}
