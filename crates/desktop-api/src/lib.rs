//! Versioned DTOs shared by the Tauri command layer and React workbench.

use std::fmt;

use codeischeap_capture_ipc::CapturedBodyState;
use codeischeap_prompt_ir::{
    Evidence, EvidenceLevel as PromptEvidenceLevel, EvidenceSource, InstructionRole, MessageRole,
    PromptIr, PromptPart,
};
use codeischeap_storage::{EncryptedStore, StorageError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ts_rs::TS;

pub const DESKTOP_API_VERSION: &str = "0.1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceBootstrap {
    pub api_version: String,
    pub source: WorkspaceSource,
    pub capture: CaptureState,
    pub requests: Vec<CapturedRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSource {
    EncryptedLocal,
    SyntheticFixture,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct CaptureState {
    pub active: bool,
    pub can_control: bool,
    pub mode: CaptureMode,
    pub profile: String,
    pub endpoint: String,
    pub storage: String,
    pub request_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    Gateway,
    Proxy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct CapturedRequest {
    pub id: String,
    pub observed_at_unix_ms: u64,
    pub application: String,
    pub provider: String,
    pub operation: String,
    pub model: String,
    pub tokens: Option<u64>,
    pub duration_ms: Option<u64>,
    pub status: CaptureStatus,
    pub has_tools: bool,
    pub prompt_preview: String,
    pub detail: RequestDetail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    Complete,
    Streaming,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct RequestDetail {
    pub anatomy: Vec<AnatomySection>,
    pub timeline: Vec<TimelineEvent>,
    pub raw: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct AnatomySection {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_count: Option<u64>,
    pub count: usize,
    pub evidence: EvidenceLevel,
    pub items: Vec<AnatomyItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    Observed,
    Derived,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct AnatomyItem {
    pub id: String,
    pub label: String,
    pub role: Option<String>,
    pub content: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub id: String,
    pub offset_ms: u64,
    pub kind: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug)]
pub enum DesktopApiError {
    Storage(StorageError),
    MissingCapture(String),
}

impl fmt::Display for DesktopApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "desktop workspace storage failed: {error}"),
            Self::MissingCapture(capture_id) => {
                write!(
                    formatter,
                    "desktop workspace capture {capture_id} disappeared"
                )
            }
        }
    }
}

impl std::error::Error for DesktopApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::MissingCapture(_) => None,
        }
    }
}

impl From<StorageError> for DesktopApiError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

pub fn load_workspace(store: &EncryptedStore) -> Result<WorkspaceBootstrap, DesktopApiError> {
    let summaries = store.list_captures(200, None)?;
    let mut requests = Vec::with_capacity(summaries.len());
    for summary in summaries {
        let capture = store
            .get_capture(&summary.capture_id)?
            .ok_or_else(|| DesktopApiError::MissingCapture(summary.capture_id.clone()))?;
        requests.push(map_capture(capture));
    }
    let cipher_version = store.cipher_version()?;
    Ok(WorkspaceBootstrap {
        api_version: DESKTOP_API_VERSION.to_owned(),
        source: WorkspaceSource::EncryptedLocal,
        capture: CaptureState {
            active: false,
            can_control: false,
            mode: CaptureMode::Gateway,
            profile: "Local encrypted workspace".to_owned(),
            endpoint: "Not connected".to_owned(),
            storage: format!("SQLCipher {cipher_version} / WAL"),
            request_count: store.capture_count()?,
        },
        requests,
    })
}

fn map_capture(capture: codeischeap_storage::StoredCapture) -> CapturedRequest {
    let envelope = capture.envelope;
    let prompt_ir = capture.prompt_ir;
    let provider_id = prompt_ir
        .as_ref()
        .map_or(capture.target_id.as_str(), |prompt| {
            prompt.provider.id.as_str()
        });
    let operation = prompt_ir
        .as_ref()
        .and_then(|prompt| prompt.operation.clone())
        .unwrap_or_else(|| envelope.request.path.clone());
    let model = prompt_ir
        .as_ref()
        .and_then(|prompt| prompt.model.clone())
        .unwrap_or_else(|| "Unknown model".to_owned());
    let prompt_preview = prompt_ir
        .as_ref()
        .and_then(prompt_preview)
        .or_else(|| {
            envelope
                .request
                .body
                .content
                .as_ref()
                .and_then(first_json_string)
        })
        .unwrap_or_else(|| "Prompt content unavailable".to_owned());
    let anatomy = prompt_ir.as_ref().map_or_else(Vec::new, anatomy_sections);
    let has_tools = prompt_ir
        .as_ref()
        .is_some_and(|prompt| !prompt.tools.is_empty());
    let application = "Unknown app".to_owned();
    let redaction_count = envelope.redactions.len();
    let raw_body = match envelope.request.body.state {
        CapturedBodyState::Json => envelope.request.body.content.clone().unwrap_or(Value::Null),
        state => json!({ "state": state, "content": envelope.request.body.content }),
    };
    let mut timeline = vec![TimelineEvent {
        id: "request_observed".to_owned(),
        offset_ms: 0,
        kind: "request".to_owned(),
        title: "Request observed".to_owned(),
        detail: format!("{} {}", envelope.request.method, envelope.request.path),
    }];
    if redaction_count > 0 {
        timeline.push(TimelineEvent {
            id: "credentials_removed".to_owned(),
            offset_ms: 0,
            kind: "security".to_owned(),
            title: "Credentials removed".to_owned(),
            detail: format!("{redaction_count} sensitive fields excluded before storage"),
        });
    }
    timeline.push(TimelineEvent {
        id: "encrypted_persistence".to_owned(),
        offset_ms: 0,
        kind: "complete".to_owned(),
        title: "Stored locally".to_owned(),
        detail: "Persisted in the encrypted SQLCipher database".to_owned(),
    });

    CapturedRequest {
        id: envelope.capture_id,
        observed_at_unix_ms: envelope.observed_at_unix_ms,
        application,
        provider: provider_label(provider_id),
        operation,
        model,
        tokens: None,
        duration_ms: None,
        status: CaptureStatus::Complete,
        has_tools,
        prompt_preview,
        detail: RequestDetail {
            anatomy,
            timeline,
            raw: json!({
                "request": {
                    "source": envelope.source,
                    "method": envelope.request.method,
                    "host": envelope.request.host,
                    "path": envelope.request.path,
                    "body": raw_body,
                },
                "redactions": envelope.redactions,
                "promptIr": prompt_ir,
            }),
        },
    }
}

fn anatomy_sections(prompt: &PromptIr) -> Vec<AnatomySection> {
    let mut sections = Vec::new();
    let instructions = prompt
        .instructions
        .iter()
        .flat_map(|instruction| {
            instruction.parts.iter().map(|part| {
                anatomy_item(
                    part,
                    instruction_role_label(instruction.role),
                    Some(instruction_role_name(instruction.role).to_owned()),
                )
            })
        })
        .collect::<Vec<_>>();
    sections.push(section(
        "instructions",
        "Instructions",
        evidence_from_instructions(prompt),
        instructions,
    ));

    let messages = prompt
        .messages
        .iter()
        .flat_map(|message| {
            message.parts.iter().map(|part| {
                anatomy_item(
                    part,
                    message_role_label(message.role),
                    Some(message_role_name(message.role).to_owned()),
                )
            })
        })
        .collect::<Vec<_>>();
    sections.push(section(
        "messages",
        "Messages",
        evidence_from_messages(prompt),
        messages,
    ));

    let tools = prompt
        .tools
        .iter()
        .map(|tool| AnatomyItem {
            id: tool.id.clone(),
            label: tool.name.clone(),
            role: None,
            content: tool
                .description
                .clone()
                .unwrap_or_else(|| compact_json(&tool.input_schema)),
            source: evidence_source(&tool.evidence),
        })
        .collect::<Vec<_>>();
    sections.push(section(
        "tools",
        "Tools",
        prompt.tools.first().map_or(EvidenceLevel::Unknown, |tool| {
            map_evidence(tool.evidence.level)
        }),
        tools,
    ));

    let mut parameters = Vec::new();
    if let Some(model) = &prompt.model {
        parameters.push(parameter_item("model", "model", model));
    }
    if let Some(operation) = &prompt.operation {
        parameters.push(parameter_item("operation", "operation", operation));
    }
    if let Some(temperature) = prompt.generation.temperature {
        parameters.push(parameter_item(
            "temperature",
            "temperature",
            &temperature.to_string(),
        ));
    }
    if let Some(max_output_tokens) = prompt.generation.max_output_tokens {
        parameters.push(parameter_item(
            "max_output_tokens",
            "max output tokens",
            &max_output_tokens.to_string(),
        ));
    }
    sections.push(section(
        "parameters",
        "Parameters",
        EvidenceLevel::Derived,
        parameters,
    ));
    sections
}

fn section(
    id: &str,
    title: &str,
    evidence: EvidenceLevel,
    items: Vec<AnatomyItem>,
) -> AnatomySection {
    AnatomySection {
        id: id.to_owned(),
        title: title.to_owned(),
        token_count: None,
        count: items.len(),
        evidence,
        items,
    }
}

fn anatomy_item(part: &PromptPart, label: &str, role: Option<String>) -> AnatomyItem {
    AnatomyItem {
        id: part.id().to_owned(),
        label: label.to_owned(),
        role,
        content: part_content(part),
        source: evidence_source(part.evidence()),
    }
}

fn parameter_item(id: &str, label: &str, content: &str) -> AnatomyItem {
    AnatomyItem {
        id: id.to_owned(),
        label: label.to_owned(),
        role: None,
        content: content.to_owned(),
        source: "Prompt IR".to_owned(),
    }
}

fn prompt_preview(prompt: &PromptIr) -> Option<String> {
    prompt
        .messages
        .iter()
        .rev()
        .filter(|message| message.role == MessageRole::User)
        .flat_map(|message| message.parts.iter())
        .find_map(text_part)
        .or_else(|| {
            prompt
                .messages
                .iter()
                .flat_map(|message| message.parts.iter())
                .find_map(text_part)
        })
        .or_else(|| {
            prompt
                .instructions
                .iter()
                .flat_map(|instruction| instruction.parts.iter())
                .find_map(text_part)
        })
}

fn text_part(part: &PromptPart) -> Option<String> {
    match part {
        PromptPart::Text { text, .. } => Some(text.clone()),
        _ => None,
    }
}

fn part_content(part: &PromptPart) -> String {
    match part {
        PromptPart::Text { text, .. } => text.clone(),
        PromptPart::Json { value, .. }
        | PromptPart::Unknown { value, .. }
        | PromptPart::ToolResult { value, .. } => compact_json(value),
        PromptPart::ImageRef { location, .. }
        | PromptPart::AudioRef { location, .. }
        | PromptPart::FileRef { location, .. } => location.clone(),
        PromptPart::ToolUse { name, input, .. } => format!("{name}: {}", compact_json(input)),
    }
}

fn evidence_from_instructions(prompt: &PromptIr) -> EvidenceLevel {
    prompt
        .instructions
        .first()
        .map_or(EvidenceLevel::Unknown, |item| {
            map_evidence(item.evidence.level)
        })
}

fn evidence_from_messages(prompt: &PromptIr) -> EvidenceLevel {
    prompt
        .messages
        .first()
        .map_or(EvidenceLevel::Unknown, |item| {
            map_evidence(item.evidence.level)
        })
}

fn map_evidence(level: PromptEvidenceLevel) -> EvidenceLevel {
    match level {
        PromptEvidenceLevel::Observed => EvidenceLevel::Observed,
        PromptEvidenceLevel::Derived => EvidenceLevel::Derived,
        PromptEvidenceLevel::Inferred => EvidenceLevel::Inferred,
        PromptEvidenceLevel::Unknown => EvidenceLevel::Unknown,
    }
}

fn evidence_source(evidence: &Evidence) -> String {
    match &evidence.source {
        Some(EvidenceSource::JsonPointer { pointer }) => pointer.clone(),
        Some(EvidenceSource::StreamEvent { index }) => format!("stream event {index}"),
        Some(EvidenceSource::Attribute { name }) => name.clone(),
        Some(EvidenceSource::ByteRange { start, end }) => format!("bytes {start}..{end}"),
        None => evidence
            .rule_id
            .clone()
            .unwrap_or_else(|| "Source unavailable".to_owned()),
    }
}

fn instruction_role_label(role: InstructionRole) -> &'static str {
    match role {
        InstructionRole::System => "System",
        InstructionRole::Developer => "Developer",
        InstructionRole::Unknown => "Unknown",
    }
}

fn instruction_role_name(role: InstructionRole) -> &'static str {
    match role {
        InstructionRole::System => "system",
        InstructionRole::Developer => "developer",
        InstructionRole::Unknown => "unknown",
    }
}

fn message_role_label(role: MessageRole) -> &'static str {
    match role {
        MessageRole::System => "System",
        MessageRole::Developer => "Developer",
        MessageRole::User => "User",
        MessageRole::Assistant => "Assistant",
        MessageRole::Tool => "Tool",
        MessageRole::Unknown => "Unknown",
    }
}

fn message_role_name(role: MessageRole) -> &'static str {
    match role {
        MessageRole::System => "system",
        MessageRole::Developer => "developer",
        MessageRole::User => "user",
        MessageRole::Assistant => "assistant",
        MessageRole::Tool => "tool",
        MessageRole::Unknown => "unknown",
    }
}

fn provider_label(provider: &str) -> String {
    match provider.to_ascii_lowercase().as_str() {
        "openai" => "OpenAI".to_owned(),
        "anthropic" => "Anthropic".to_owned(),
        "google" => "Google".to_owned(),
        "mistral" => "Mistral".to_owned(),
        _ => provider.to_owned(),
    }
}

fn first_json_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Array(values) => values.iter().find_map(first_json_string),
        Value::Object(values) => values.values().find_map(first_json_string),
        _ => None,
    }
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<invalid JSON>".to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use codeischeap_capture_ipc::{
        CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureSource, CapturedBody, CapturedBodyState,
        CapturedField, CapturedRequest,
    };
    use codeischeap_capture_policy::CapturePolicy;
    use codeischeap_prompt_ir::PromptIr;
    use codeischeap_storage::{DatabaseKey, EncryptedStore};
    use tempfile::tempdir;
    use ts_rs::{Config, TS};

    use super::*;

    #[test]
    fn encrypted_capture_maps_to_the_versioned_desktop_contract() {
        let directory = tempdir().expect("temp directory must be created");
        let mut store = EncryptedStore::open(
            directory.path().join("captures.db"),
            DatabaseKey::from_bytes([0x51; 32]),
        )
        .expect("encrypted store must open");
        let policy = CapturePolicy::load_default().expect("policy must load");
        let envelope = CaptureEnvelope {
            version: CAPTURE_ENVELOPE_VERSION.to_owned(),
            capture_id: "desktop_capture_1".to_owned(),
            observed_at_unix_ms: 1_721_000_000_250,
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
                    value: "Bearer desktop-api-canary".to_owned(),
                }],
                body: CapturedBody {
                    state: CapturedBodyState::Json,
                    content: Some(json!({"input": "Fix the failing parser test."})),
                },
            },
            redactions: Vec::new(),
        };
        let sanitized = policy
            .sanitize_envelope(envelope)
            .expect("fixture must be in scope");
        let mut prompt: PromptIr = serde_json::from_str(include_str!(
            "../../prompt-ir/tests/fixtures/basic-openai.json"
        ))
        .expect("Prompt IR fixture must parse");
        prompt.request_id = "desktop_capture_1".to_owned();
        store
            .upsert_capture(&sanitized, Some(&prompt))
            .expect("capture must persist");

        let workspace = load_workspace(&store).expect("workspace must load");

        assert_eq!(workspace.api_version, DESKTOP_API_VERSION);
        assert_eq!(workspace.source, WorkspaceSource::EncryptedLocal);
        assert_eq!(workspace.capture.request_count, 1);
        assert_eq!(workspace.requests[0].provider, "OpenAI");
        assert_eq!(
            workspace.requests[0].prompt_preview,
            "Fix the failing parser test."
        );
        assert!(workspace.requests[0].has_tools);
        let encoded = serde_json::to_string(&workspace).expect("workspace must encode");
        assert!(!encoded.contains("desktop-api-canary"));
        assert!(encoded.contains("SQLCipher"));
    }

    #[test]
    fn checked_in_schema_matches_the_rust_contract() {
        let generated = serde_json::to_value(schemars::schema_for!(WorkspaceBootstrap))
            .expect("schema must serialize");
        let checked_in: Value = serde_json::from_str(include_str!(
            "../../../schemas/desktop-api/v0.1.schema.json"
        ))
        .expect("checked-in schema must parse");

        assert_eq!(checked_in, generated);
    }

    #[test]
    fn checked_in_typescript_matches_the_rust_contract() {
        let generated = tempdir().expect("binding directory must be created");
        let config = Config::new()
            .with_out_dir(generated.path())
            .with_large_int("number");
        WorkspaceBootstrap::export_all(&config).expect("bindings must export");
        let checked_in = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../apps/desktop/src/generated/desktop-api");

        assert_eq!(read_bindings(&checked_in), read_bindings(generated.path()));
    }

    fn read_bindings(directory: &Path) -> Vec<(PathBuf, String)> {
        let mut pending = vec![directory.to_path_buf()];
        let mut bindings = Vec::new();
        while let Some(current) = pending.pop() {
            for entry in fs::read_dir(&current).expect("binding directory must be readable") {
                let entry = entry.expect("binding entry must be readable");
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let relative = path
                        .strip_prefix(directory)
                        .expect("binding must be under its root")
                        .to_path_buf();
                    let content = fs::read_to_string(path).expect("binding must be UTF-8");
                    bindings.push((relative, content));
                }
            }
        }
        bindings.sort_by(|left, right| left.0.cmp(&right.0));
        bindings
    }
}
