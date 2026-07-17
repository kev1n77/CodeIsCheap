use std::collections::BTreeMap;

use codeischeap_capture_ipc::CapturedBodyState;
use codeischeap_prompt_ir::{
    BodyState, Completeness, ContextItem, ContextKind, Evidence, EvidenceSource, GenerationOptions,
    Instruction, InstructionRole, Message, MessageRole, PromptIr, PromptPart, ToolDefinition,
};
use serde_json::{Map, Value, json};

use crate::model::{
    AdapterError, AdapterInput, AdapterOutput, ParseIssue, ParseIssueCode, PromptAdapter,
};
use crate::ollama_response::parse_ollama_response;

pub const OLLAMA_ADAPTER_ID: &str = "ollama/v0.1";

#[derive(Debug, Clone, Copy, Default)]
pub struct OllamaAdapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OllamaOperation {
    Chat,
    Generate,
}

impl OllamaOperation {
    const fn name(self) -> &'static str {
        match self {
            Self::Chat => "chat.create",
            Self::Generate => "generate.create",
        }
    }
}

impl PromptAdapter for OllamaAdapter {
    fn id(&self) -> &'static str {
        OLLAMA_ADAPTER_ID
    }

    fn detect(&self, input: AdapterInput<'_>) -> Option<f32> {
        (input.target_id == "ollama" && operation(&input.envelope.request.path).is_some())
            .then_some(1.0)
    }

    fn parse(&self, input: AdapterInput<'_>) -> Result<AdapterOutput, AdapterError> {
        if input.envelope.request.body.state != CapturedBodyState::Json {
            return Err(AdapterError::at(
                ParseIssueCode::InvalidBody,
                "/request/body",
            ));
        }
        let body = input
            .envelope
            .request
            .body
            .content
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| {
                AdapterError::at(ParseIssueCode::InvalidBody, "/request/body/content")
            })?;
        let operation = operation(&input.envelope.request.path).ok_or_else(|| {
            AdapterError::at(ParseIssueCode::UnsupportedOperation, "/request/path")
        })?;
        let streaming = body.get("stream").and_then(Value::as_bool).unwrap_or(true);

        let mut prompt = PromptIr::new(&input.envelope.capture_id, "ollama");
        prompt.provider.host = Some(input.envelope.request.host.clone());
        prompt.provider.confidence = Some(1.0);
        prompt.operation = Some(operation.name().to_owned());
        prompt.model = body.get("model").and_then(Value::as_str).map(str::to_owned);
        prompt.generation = parse_generation(body.get("options"));
        prompt.completeness = Completeness {
            request_body: BodyState::Complete,
            response_body: BodyState::Missing,
        };
        prompt
            .vendor
            .insert("stream".to_owned(), Value::Bool(streaming));
        copy_vendor_fields(body, &mut prompt.vendor);

        let mut issues = Vec::new();
        if prompt.model.is_none() {
            issues.push(ParseIssue::at(
                OLLAMA_ADAPTER_ID,
                ParseIssueCode::MissingField,
                "/model",
            ));
        }
        match operation {
            OllamaOperation::Chat => parse_chat(body, &mut prompt, &mut issues),
            OllamaOperation::Generate => parse_generate(body, &mut prompt, &mut issues),
        }
        prompt.tools = parse_tools(body.get("tools"), &mut issues);
        parse_ollama_response(
            input.envelope.outcome.as_ref(),
            operation,
            streaming,
            &mut prompt,
            &mut issues,
        );

        Ok(AdapterOutput {
            prompt_ir: prompt,
            issues,
        })
    }
}

fn operation(path: &str) -> Option<OllamaOperation> {
    match path {
        "/api/chat" => Some(OllamaOperation::Chat),
        "/api/generate" => Some(OllamaOperation::Generate),
        _ => None,
    }
}

fn parse_chat(body: &Map<String, Value>, prompt: &mut PromptIr, issues: &mut Vec<ParseIssue>) {
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        issues.push(ParseIssue::at(
            OLLAMA_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/messages",
        ));
        return;
    };
    for (index, value) in messages.iter().enumerate() {
        parse_chat_message(value, index, prompt, issues);
    }
}

fn parse_chat_message(
    value: &Value,
    index: usize,
    prompt: &mut PromptIr,
    issues: &mut Vec<ParseIssue>,
) {
    let pointer = format!("/messages/{index}");
    let Some(object) = value.as_object() else {
        issues.push(ParseIssue::at(
            OLLAMA_ADAPTER_ID,
            ParseIssueCode::InvalidField,
            pointer,
        ));
        return;
    };
    let role = message_role(object.get("role").and_then(Value::as_str));
    if role == MessageRole::Unknown {
        issues.push(ParseIssue::at(
            OLLAMA_ADAPTER_ID,
            ParseIssueCode::InvalidField,
            format!("{pointer}/role"),
        ));
    }
    if role == MessageRole::System {
        let id = format!("instruction_{index}");
        prompt.instructions.push(Instruction {
            id: id.clone(),
            role: InstructionRole::System,
            parts: message_parts(object, &pointer, &id, role, issues),
            evidence: observed(pointer),
        });
        return;
    }

    let id = format!("message_{index}");
    prompt.messages.push(Message {
        id: id.clone(),
        role,
        parts: message_parts(object, &pointer, &id, role, issues),
        evidence: observed(pointer),
    });
}

fn message_parts(
    object: &Map<String, Value>,
    pointer: &str,
    id_prefix: &str,
    role: MessageRole,
    issues: &mut Vec<ParseIssue>,
) -> Vec<PromptPart> {
    let mut parts = Vec::new();
    if role == MessageRole::Tool {
        let tool_name = object
            .get("tool_name")
            .or_else(|| object.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("unknown_tool_use");
        parts.push(PromptPart::ToolResult {
            id: format!("{id_prefix}_part_0"),
            tool_use_id: tool_name.to_owned(),
            value: object.get("content").cloned().unwrap_or(Value::Null),
            evidence: observed(format!("{pointer}/content")),
        });
    } else if let Some(content) = object.get("content").and_then(Value::as_str)
        && !content.is_empty()
    {
        parts.push(PromptPart::Text {
            id: format!("{id_prefix}_part_0"),
            text: content.to_owned(),
            evidence: observed(format!("{pointer}/content")),
        });
    }
    if let Some(thinking) = object.get("thinking").and_then(Value::as_str) {
        parts.push(PromptPart::Json {
            id: format!("{id_prefix}_part_{}", parts.len()),
            value: json!({"type": "thinking", "thinking": thinking}),
            evidence: observed(format!("{pointer}/thinking")),
        });
    }
    append_images(
        object.get("images"),
        &format!("{pointer}/images"),
        id_prefix,
        &mut parts,
        issues,
    );
    if let Some(calls) = object.get("tool_calls").and_then(Value::as_array) {
        for (call_index, call) in calls.iter().enumerate() {
            let call_pointer = format!("{pointer}/tool_calls/{call_index}");
            let fallback_id = format!("{id_prefix}_tool_{call_index}");
            parts.push(parse_tool_call_with_evidence(
                call,
                &fallback_id,
                observed(&call_pointer),
                &call_pointer,
                issues,
            ));
        }
    }
    parts
}

fn parse_generate(body: &Map<String, Value>, prompt: &mut PromptIr, issues: &mut Vec<ParseIssue>) {
    if let Some(system) = body.get("system").and_then(Value::as_str) {
        prompt.instructions.push(Instruction {
            id: "instruction_0".to_owned(),
            role: InstructionRole::System,
            parts: vec![PromptPart::Text {
                id: "instruction_0_part_0".to_owned(),
                text: system.to_owned(),
                evidence: observed("/system"),
            }],
            evidence: observed("/system"),
        });
    }
    let id = "message_0";
    let mut parts = Vec::new();
    if let Some(prompt_text) = body.get("prompt").and_then(Value::as_str) {
        parts.push(PromptPart::Text {
            id: format!("{id}_part_0"),
            text: prompt_text.to_owned(),
            evidence: observed("/prompt"),
        });
    } else {
        issues.push(ParseIssue::at(
            OLLAMA_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/prompt",
        ));
    }
    append_images(body.get("images"), "/images", id, &mut parts, issues);
    prompt.messages.push(Message {
        id: id.to_owned(),
        role: MessageRole::User,
        parts,
        evidence: observed("/prompt"),
    });
    if let Some(suffix) = body.get("suffix").and_then(Value::as_str) {
        prompt.context.push(ContextItem {
            id: "context_suffix".to_owned(),
            kind: ContextKind::ApplicationState,
            source_label: Some("suffix".to_owned()),
            parts: vec![PromptPart::Text {
                id: "context_suffix_part_0".to_owned(),
                text: suffix.to_owned(),
                evidence: observed("/suffix"),
            }],
            evidence: observed("/suffix"),
        });
    }
}

fn append_images(
    value: Option<&Value>,
    pointer: &str,
    id_prefix: &str,
    parts: &mut Vec<PromptPart>,
    issues: &mut Vec<ParseIssue>,
) {
    let Some(images) = value.and_then(Value::as_array) else {
        return;
    };
    for (index, image) in images.iter().enumerate() {
        if !image.is_string() {
            issues.push(ParseIssue::at(
                OLLAMA_ADAPTER_ID,
                ParseIssueCode::InvalidField,
                format!("{pointer}/{index}"),
            ));
        }
        parts.push(PromptPart::ImageRef {
            id: format!("{id_prefix}_part_{}", parts.len()),
            location: "inline:base64".to_owned(),
            media_type: None,
            evidence: observed(format!("{pointer}/{index}")),
        });
    }
}

pub(crate) fn parse_tool_call_with_evidence(
    value: &Value,
    fallback_id: &str,
    evidence: Evidence,
    issue_path: &str,
    issues: &mut Vec<ParseIssue>,
) -> PromptPart {
    let function = value
        .get("function")
        .and_then(Value::as_object)
        .or_else(|| value.as_object());
    let name = function
        .and_then(|function| function.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown_tool")
        .to_owned();
    if name == "unknown_tool" {
        issues.push(ParseIssue::at(
            OLLAMA_ADAPTER_ID,
            ParseIssueCode::MissingField,
            format!("{issue_path}/function/name"),
        ));
    }
    let input = function
        .and_then(|function| function.get("arguments"))
        .map(parse_json_string)
        .unwrap_or_else(|| json!({}));
    PromptPart::ToolUse {
        id: value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .unwrap_or(fallback_id)
            .to_owned(),
        name,
        input,
        evidence,
    }
}

fn parse_tools(value: Option<&Value>, issues: &mut Vec<ParseIssue>) -> Vec<ToolDefinition> {
    let Some(tools) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    tools
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            let pointer = format!("/tools/{index}");
            let function = value
                .get("function")
                .and_then(Value::as_object)
                .or_else(|| value.as_object())?;
            let Some(name) = function.get("name").and_then(Value::as_str) else {
                issues.push(ParseIssue::at(
                    OLLAMA_ADAPTER_ID,
                    ParseIssueCode::MissingField,
                    format!("{pointer}/function/name"),
                ));
                return None;
            };
            Some(ToolDefinition {
                id: format!("tool_{index}"),
                name: name.to_owned(),
                description: function
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                input_schema: function
                    .get("parameters")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                evidence: observed(pointer),
            })
        })
        .collect()
}

fn parse_generation(value: Option<&Value>) -> GenerationOptions {
    let Some(options) = value.and_then(Value::as_object) else {
        return GenerationOptions::default();
    };
    let stop = match options.get("stop") {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    let temperature = options.get("temperature").and_then(Value::as_f64);
    let top_p = options.get("top_p").and_then(Value::as_f64);
    let max_output_tokens = options.get("num_predict").and_then(Value::as_u64);
    let mut extra = BTreeMap::new();
    for (key, value) in options {
        let mapped = match key.as_str() {
            "temperature" => temperature.is_some(),
            "top_p" => top_p.is_some(),
            "num_predict" => max_output_tokens.is_some(),
            "stop" => matches!(value, Value::String(_) | Value::Array(_)),
            _ => false,
        };
        if !mapped {
            extra.insert(key.clone(), value.clone());
        }
    }
    GenerationOptions {
        temperature,
        top_p,
        max_output_tokens,
        stop,
        extra,
    }
}

fn copy_vendor_fields(body: &Map<String, Value>, vendor: &mut BTreeMap<String, Value>) {
    for key in [
        "format",
        "keep_alive",
        "think",
        "raw",
        "template",
        "context",
    ] {
        if let Some(value) = body.get(key) {
            vendor.insert(key.to_owned(), value.clone());
        }
    }
}

fn message_role(role: Option<&str>) -> MessageRole {
    match role {
        Some("system") => MessageRole::System,
        Some("user") => MessageRole::User,
        Some("assistant") => MessageRole::Assistant,
        Some("tool") => MessageRole::Tool,
        _ => MessageRole::Unknown,
    }
}

fn parse_json_string(value: &Value) -> Value {
    match value {
        Value::String(value) => {
            serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.clone()))
        }
        _ => value.clone(),
    }
}

fn observed(pointer: impl Into<String>) -> Evidence {
    Evidence::observed(EvidenceSource::JsonPointer {
        pointer: pointer.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_documented_ollama_operations_are_detected() {
        assert_eq!(operation("/api/chat"), Some(OllamaOperation::Chat));
        assert_eq!(operation("/api/generate"), Some(OllamaOperation::Generate));
        assert_eq!(operation("/api/embed"), None);
    }

    #[test]
    fn sentinel_num_predict_is_preserved_as_vendor_option() {
        let generation = parse_generation(Some(&json!({"num_predict": -1})));

        assert_eq!(generation.max_output_tokens, None);
        assert_eq!(generation.extra["num_predict"], -1);
    }
}
