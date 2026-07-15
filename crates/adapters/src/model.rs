use std::fmt;

use codeischeap_capture_ipc::CaptureEnvelope;
use codeischeap_capture_policy::SanitizedCapture;
use codeischeap_prompt_ir::PromptIr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub struct AdapterInput<'a> {
    pub target_id: &'a str,
    pub envelope: &'a CaptureEnvelope,
}

impl<'a> From<&'a SanitizedCapture> for AdapterInput<'a> {
    fn from(capture: &'a SanitizedCapture) -> Self {
        Self {
            target_id: capture.target_id(),
            envelope: capture.envelope(),
        }
    }
}

pub trait PromptAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, input: AdapterInput<'_>) -> Option<f32>;
    fn parse(&self, input: AdapterInput<'_>) -> Result<AdapterOutput, AdapterError>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdapterOutput {
    pub prompt_ir: PromptIr,
    pub issues: Vec<ParseIssue>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParseResult {
    pub adapter_id: Option<String>,
    pub confidence: Option<f32>,
    pub prompt_ir: Option<PromptIr>,
    pub issues: Vec<ParseIssue>,
    pub raw_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseIssueCode {
    NoAdapter,
    AdapterRejected,
    AdapterPanicked,
    AllAdaptersFailed,
    InvalidBody,
    InvalidStreamEvent,
    UnsupportedOperation,
    MissingField,
    UnsupportedContent,
    InvalidField,
    InvalidPromptIr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseIssue {
    pub adapter_id: Option<String>,
    pub code: ParseIssueCode,
    pub path: Option<String>,
}

impl ParseIssue {
    pub(crate) fn adapter(adapter_id: &str, code: ParseIssueCode) -> Self {
        Self {
            adapter_id: Some(adapter_id.to_owned()),
            code,
            path: None,
        }
    }

    pub(crate) fn at(adapter_id: &str, code: ParseIssueCode, path: impl Into<String>) -> Self {
        Self {
            adapter_id: Some(adapter_id.to_owned()),
            code,
            path: Some(path.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterError {
    pub code: ParseIssueCode,
    pub path: Option<String>,
}

impl AdapterError {
    pub const fn new(code: ParseIssueCode) -> Self {
        Self { code, path: None }
    }

    pub fn at(code: ParseIssueCode, path: impl Into<String>) -> Self {
        Self {
            code,
            path: Some(path.into()),
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "provider adapter rejected the sanitized capture")
    }
}

impl std::error::Error for AdapterError {}
