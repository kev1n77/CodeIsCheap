use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Evidence;

pub const PROMPT_IR_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderRef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InstructionRole {
    System,
    Developer,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Instruction {
    pub id: String,
    pub role: InstructionRole,
    #[serde(default)]
    pub parts: Vec<PromptPart>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    System,
    Developer,
    User,
    Assistant,
    Tool,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Message {
    pub id: String,
    pub role: MessageRole,
    #[serde(default)]
    pub parts: Vec<PromptPart>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PromptPart {
    Text {
        id: String,
        text: String,
        evidence: Evidence,
    },
    Json {
        id: String,
        value: Value,
        evidence: Evidence,
    },
    ImageRef {
        id: String,
        location: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
        evidence: Evidence,
    },
    AudioRef {
        id: String,
        location: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
        evidence: Evidence,
    },
    FileRef {
        id: String,
        location: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
        evidence: Evidence,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
        evidence: Evidence,
    },
    ToolResult {
        id: String,
        tool_use_id: String,
        value: Value,
        evidence: Evidence,
    },
    Unknown {
        id: String,
        value: Value,
        evidence: Evidence,
    },
}

impl PromptPart {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Text { id, .. }
            | Self::Json { id, .. }
            | Self::ImageRef { id, .. }
            | Self::AudioRef { id, .. }
            | Self::FileRef { id, .. }
            | Self::ToolUse { id, .. }
            | Self::ToolResult { id, .. }
            | Self::Unknown { id, .. } => id,
        }
    }

    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        match self {
            Self::Text { evidence, .. }
            | Self::Json { evidence, .. }
            | Self::ImageRef { evidence, .. }
            | Self::AudioRef { evidence, .. }
            | Self::FileRef { evidence, .. }
            | Self::ToolUse { evidence, .. }
            | Self::ToolResult { evidence, .. }
            | Self::Unknown { evidence, .. } => evidence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    RetrievedDocument,
    CachedContent,
    ToolResult,
    ApplicationState,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ContextItem {
    pub id: String,
    pub kind: ContextKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_label: Option<String>,
    #[serde(default)]
    pub parts: Vec<PromptPart>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolDefinition {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResponseTrace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub role: MessageRole,
    #[serde(default)]
    pub parts: Vec<PromptPart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_sequence: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub usage: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(default)]
    pub events: Vec<ResponseEvent>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResponseEvent {
    pub index: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_index: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_kind: Option<String>,
    pub evidence: Evidence,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct GenerationOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BodyState {
    Complete,
    Partial,
    Streaming,
    Missing,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Completeness {
    pub request_body: BodyState,
    pub response_body: BodyState,
}

impl Default for Completeness {
    fn default() -> Self {
        Self {
            request_body: BodyState::Complete,
            response_body: BodyState::Missing,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PromptIr {
    pub ir_version: String,
    pub request_id: String,
    pub provider: ProviderRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default)]
    pub instructions: Vec<Instruction>,
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub context: Vec<ContextItem>,
    #[serde(default)]
    pub tools: Vec<ToolDefinition>,
    #[serde(default)]
    pub generation: GenerationOptions,
    #[serde(default)]
    pub vendor: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseTrace>,
    #[serde(default)]
    pub completeness: Completeness,
}

impl PromptIr {
    #[must_use]
    pub fn new(request_id: impl Into<String>, provider_id: impl Into<String>) -> Self {
        Self {
            ir_version: PROMPT_IR_VERSION.to_owned(),
            request_id: request_id.into(),
            provider: ProviderRef {
                id: provider_id.into(),
                host: None,
                confidence: None,
            },
            operation: None,
            model: None,
            instructions: Vec::new(),
            messages: Vec::new(),
            context: Vec::new(),
            tools: Vec::new(),
            generation: GenerationOptions::default(),
            vendor: BTreeMap::new(),
            response: None,
            completeness: Completeness::default(),
        }
    }
}
