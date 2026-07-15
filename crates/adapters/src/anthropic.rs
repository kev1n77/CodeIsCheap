use std::collections::BTreeMap;

use codeischeap_capture_ipc::{CapturedBodyState, CapturedField};
use codeischeap_prompt_ir::{
    BodyState, Completeness, Evidence, EvidenceSource, GenerationOptions, Instruction,
    InstructionRole, Message, MessageRole, PromptIr, PromptPart, ToolDefinition,
};
use serde_json::{Map, Value, json};

use crate::anthropic_response::parse_anthropic_response;
use crate::model::{
    AdapterError, AdapterInput, AdapterOutput, ParseIssue, ParseIssueCode, PromptAdapter,
};

pub const ANTHROPIC_ADAPTER_ID: &str = "anthropic/v0.1";

#[derive(Debug, Clone, Copy, Default)]
pub struct AnthropicAdapter;

impl PromptAdapter for AnthropicAdapter {
    fn id(&self) -> &'static str {
        ANTHROPIC_ADAPTER_ID
    }

    fn detect(&self, input: AdapterInput<'_>) -> Option<f32> {
        let supported_path = matches!(
            input.envelope.request.path.as_str(),
            "/v1/messages" | "/v1/complete"
        );
        (input.target_id == "anthropic" && supported_path).then_some(1.0)
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
        let mut prompt = PromptIr::new(&input.envelope.capture_id, "anthropic");
        prompt.provider.host = Some(input.envelope.request.host.clone());
        prompt.provider.confidence = Some(1.0);
        prompt.model = body.get("model").and_then(Value::as_str).map(str::to_owned);
        prompt.generation = parse_generation(body);
        prompt.completeness = Completeness {
            request_body: BodyState::Complete,
            response_body: BodyState::Missing,
        };
        copy_vendor_fields(body, &input.envelope.request.headers, &mut prompt.vendor);

        let mut issues = Vec::new();
        if prompt.model.is_none() {
            issues.push(ParseIssue::at(
                ANTHROPIC_ADAPTER_ID,
                ParseIssueCode::MissingField,
                "/model",
            ));
        }
        if body.get("max_tokens").and_then(Value::as_u64).is_none() {
            issues.push(ParseIssue::at(
                ANTHROPIC_ADAPTER_ID,
                ParseIssueCode::MissingField,
                "/max_tokens",
            ));
        }

        match input.envelope.request.path.as_str() {
            "/v1/messages" => parse_messages_request(body, &mut prompt, &mut issues),
            "/v1/complete" => parse_complete_request(body, &mut prompt, &mut issues),
            _ => {
                return Err(AdapterError::at(
                    ParseIssueCode::UnsupportedOperation,
                    "/request/path",
                ));
            }
        }
        prompt.tools = parse_tools(body.get("tools"), &mut issues);
        parse_anthropic_response(
            input.envelope.outcome.as_ref(),
            &input.envelope.request.path,
            &mut prompt,
            &mut issues,
        );
        Ok(AdapterOutput {
            prompt_ir: prompt,
            issues,
        })
    }
}

fn parse_messages_request(
    body: &Map<String, Value>,
    prompt: &mut PromptIr,
    issues: &mut Vec<ParseIssue>,
) {
    prompt.operation = Some("messages.create".to_owned());
    parse_system(body.get("system"), prompt, issues);
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        issues.push(ParseIssue::at(
            ANTHROPIC_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/messages",
        ));
        return;
    };
    for (index, value) in messages.iter().enumerate() {
        parse_message(value, index, prompt, issues);
    }
}

fn parse_complete_request(
    body: &Map<String, Value>,
    prompt: &mut PromptIr,
    issues: &mut Vec<ParseIssue>,
) {
    prompt.operation = Some("completions.create".to_owned());
    let Some(value) = body.get("prompt") else {
        issues.push(ParseIssue::at(
            ANTHROPIC_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/prompt",
        ));
        return;
    };
    prompt.messages.push(Message {
        id: "message_0".to_owned(),
        role: MessageRole::User,
        parts: parse_content(value, "/prompt", "message_0", issues),
        evidence: observed("/prompt"),
    });
}

fn parse_system(value: Option<&Value>, prompt: &mut PromptIr, issues: &mut Vec<ParseIssue>) {
    let Some(value) = value else {
        return;
    };
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let pointer = format!("/system/{index}");
                let id = format!("instruction_{index}");
                prompt.instructions.push(Instruction {
                    id: id.clone(),
                    role: InstructionRole::System,
                    parts: parse_content(value, &pointer, &id, issues),
                    evidence: observed(pointer),
                });
            }
        }
        Value::String(_) | Value::Object(_) => prompt.instructions.push(Instruction {
            id: "instruction_0".to_owned(),
            role: InstructionRole::System,
            parts: parse_content(value, "/system", "instruction_0", issues),
            evidence: observed("/system"),
        }),
        _ => issues.push(ParseIssue::at(
            ANTHROPIC_ADAPTER_ID,
            ParseIssueCode::InvalidField,
            "/system",
        )),
    }
}

fn parse_message(value: &Value, index: usize, prompt: &mut PromptIr, issues: &mut Vec<ParseIssue>) {
    let pointer = format!("/messages/{index}");
    let Some(object) = value.as_object() else {
        issues.push(ParseIssue::at(
            ANTHROPIC_ADAPTER_ID,
            ParseIssueCode::InvalidField,
            pointer,
        ));
        return;
    };
    let content = object.get("content").unwrap_or(&Value::Null);
    let role = match object.get("role").and_then(Value::as_str) {
        Some("user") if all_tool_results(content) => MessageRole::Tool,
        Some("user") => MessageRole::User,
        Some("assistant") => MessageRole::Assistant,
        _ => {
            issues.push(ParseIssue::at(
                ANTHROPIC_ADAPTER_ID,
                ParseIssueCode::InvalidField,
                format!("{pointer}/role"),
            ));
            MessageRole::Unknown
        }
    };
    let id = format!("message_{index}");
    prompt.messages.push(Message {
        id: id.clone(),
        role,
        parts: parse_content(content, &format!("{pointer}/content"), &id, issues),
        evidence: observed(pointer),
    });
}

fn all_tool_results(content: &Value) -> bool {
    let Some(blocks) = content.as_array() else {
        return false;
    };
    !blocks.is_empty()
        && blocks
            .iter()
            .all(|block| block.get("type").and_then(Value::as_str) == Some("tool_result"))
}

fn parse_content(
    value: &Value,
    pointer: &str,
    id_prefix: &str,
    issues: &mut Vec<ParseIssue>,
) -> Vec<PromptPart> {
    match value {
        Value::Null => Vec::new(),
        Value::String(text) => vec![PromptPart::Text {
            id: format!("{id_prefix}_part_0"),
            text: text.clone(),
            evidence: observed(pointer),
        }],
        Value::Array(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                parse_content_block(
                    value,
                    &format!("{pointer}/{index}"),
                    &format!("{id_prefix}_part_{index}"),
                    issues,
                )
            })
            .collect(),
        _ => vec![parse_content_block(
            value,
            pointer,
            &format!("{id_prefix}_part_0"),
            issues,
        )],
    }
}

fn parse_content_block(
    value: &Value,
    pointer: &str,
    fallback_id: &str,
    issues: &mut Vec<ParseIssue>,
) -> PromptPart {
    let Some(object) = value.as_object() else {
        return PromptPart::Json {
            id: fallback_id.to_owned(),
            value: value.clone(),
            evidence: observed(pointer),
        };
    };
    match object.get("type").and_then(Value::as_str) {
        Some("text") | None if object.get("text").is_some() => PromptPart::Text {
            id: fallback_id.to_owned(),
            text: object
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            evidence: observed(pointer),
        },
        Some("image") => media_part(object, pointer, fallback_id, true),
        Some("document") => media_part(object, pointer, fallback_id, false),
        Some("tool_use" | "server_tool_use") => {
            let id = object
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .unwrap_or(fallback_id)
                .to_owned();
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown_tool")
                .to_owned();
            if object.get("name").and_then(Value::as_str).is_none() {
                issues.push(ParseIssue::at(
                    ANTHROPIC_ADAPTER_ID,
                    ParseIssueCode::MissingField,
                    format!("{pointer}/name"),
                ));
            }
            PromptPart::ToolUse {
                id,
                name,
                input: object.get("input").cloned().unwrap_or_else(|| json!({})),
                evidence: observed(pointer),
            }
        }
        Some("tool_result" | "web_search_tool_result") => {
            let tool_use_id = object
                .get("tool_use_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown_tool_use")
                .to_owned();
            if object.get("tool_use_id").and_then(Value::as_str).is_none() {
                issues.push(ParseIssue::at(
                    ANTHROPIC_ADAPTER_ID,
                    ParseIssueCode::MissingField,
                    format!("{pointer}/tool_use_id"),
                ));
            }
            let mut result = Map::new();
            result.insert(
                "content".to_owned(),
                object.get("content").cloned().unwrap_or(Value::Null),
            );
            if let Some(is_error) = object.get("is_error") {
                result.insert("is_error".to_owned(), is_error.clone());
            }
            PromptPart::ToolResult {
                id: fallback_id.to_owned(),
                tool_use_id,
                value: Value::Object(result),
                evidence: observed(pointer),
            }
        }
        _ => {
            issues.push(ParseIssue::at(
                ANTHROPIC_ADAPTER_ID,
                ParseIssueCode::UnsupportedContent,
                pointer,
            ));
            PromptPart::Unknown {
                id: fallback_id.to_owned(),
                value: value.clone(),
                evidence: observed(pointer),
            }
        }
    }
}

fn media_part(object: &Map<String, Value>, pointer: &str, id: &str, image: bool) -> PromptPart {
    let source = object.get("source").and_then(Value::as_object);
    let location = source
        .and_then(|source| source.get("url").and_then(Value::as_str))
        .map(str::to_owned)
        .or_else(|| {
            source
                .and_then(|source| source.get("file_id").and_then(Value::as_str))
                .map(|file_id| format!("file:{file_id}"))
        })
        .or_else(|| {
            source
                .and_then(|source| source.get("data"))
                .map(|_| "inline:base64".to_owned())
        })
        .unwrap_or_else(|| "unknown media location".to_owned());
    let media_type = source
        .and_then(|source| source.get("media_type").and_then(Value::as_str))
        .map(str::to_owned);
    let evidence = observed(pointer);
    if image {
        PromptPart::ImageRef {
            id: id.to_owned(),
            location,
            media_type,
            evidence,
        }
    } else {
        PromptPart::FileRef {
            id: id.to_owned(),
            location,
            media_type,
            evidence,
        }
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
            let object = value.as_object()?;
            let Some(name) = object.get("name").and_then(Value::as_str) else {
                issues.push(ParseIssue::at(
                    ANTHROPIC_ADAPTER_ID,
                    ParseIssueCode::MissingField,
                    format!("{pointer}/name"),
                ));
                return None;
            };
            if object.get("input_schema").is_none() {
                issues.push(ParseIssue::at(
                    ANTHROPIC_ADAPTER_ID,
                    ParseIssueCode::MissingField,
                    format!("{pointer}/input_schema"),
                ));
            }
            Some(ToolDefinition {
                id: format!("tool_definition_{index}"),
                name: name.to_owned(),
                description: object
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                input_schema: object
                    .get("input_schema")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                evidence: observed(pointer),
            })
        })
        .collect()
}

fn parse_generation(body: &Map<String, Value>) -> GenerationOptions {
    let stop = body
        .get("stop_sequences")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut extra = BTreeMap::new();
    if let Some(top_k) = body.get("top_k") {
        extra.insert("top_k".to_owned(), top_k.clone());
    }
    GenerationOptions {
        temperature: body.get("temperature").and_then(Value::as_f64),
        top_p: body.get("top_p").and_then(Value::as_f64),
        max_output_tokens: body.get("max_tokens").and_then(Value::as_u64),
        stop,
        extra,
    }
}

fn copy_vendor_fields(
    body: &Map<String, Value>,
    headers: &[CapturedField],
    vendor: &mut BTreeMap<String, Value>,
) {
    for key in [
        "stream",
        "tool_choice",
        "metadata",
        "thinking",
        "service_tier",
    ] {
        if let Some(value) = body.get(key) {
            vendor.insert(key.to_owned(), value.clone());
        }
    }
    for (header, key) in [
        ("anthropic-version", "anthropic_version"),
        ("anthropic-beta", "anthropic_beta"),
    ] {
        if let Some(value) = headers
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(header))
            .map(|field| field.value.clone())
        {
            vendor.insert(key.to_owned(), Value::String(value));
        }
    }
}

fn observed(pointer: impl Into<String>) -> Evidence {
    Evidence::observed(EvidenceSource::JsonPointer {
        pointer: pointer.into(),
    })
}
