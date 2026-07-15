use std::collections::BTreeMap;

use codeischeap_capture_ipc::CapturedBodyState;
use codeischeap_prompt_ir::{
    BodyState, Completeness, Evidence, EvidenceSource, GenerationOptions, Instruction,
    InstructionRole, Message, MessageRole, PromptIr, PromptPart, ToolDefinition,
};
use serde_json::{Map, Value, json};

use crate::model::{
    AdapterError, AdapterInput, AdapterOutput, ParseIssue, ParseIssueCode, PromptAdapter,
};

pub const OPENAI_ADAPTER_ID: &str = "openai-compatible/v0.1";

#[derive(Debug, Clone, Copy, Default)]
pub struct OpenAiAdapter;

impl PromptAdapter for OpenAiAdapter {
    fn id(&self) -> &'static str {
        OPENAI_ADAPTER_ID
    }

    fn detect(&self, input: AdapterInput<'_>) -> Option<f32> {
        let supported_path = matches!(
            input.envelope.request.path.as_str(),
            "/v1/responses" | "/v1/chat/completions" | "/v1/completions"
        );
        (input.target_id == "openai" && supported_path).then_some(1.0)
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
        let mut prompt = PromptIr::new(&input.envelope.capture_id, "openai");
        prompt.provider.host = Some(input.envelope.request.host.clone());
        prompt.provider.confidence = Some(1.0);
        prompt.model = body.get("model").and_then(Value::as_str).map(str::to_owned);
        prompt.generation = parse_generation(body);
        prompt.completeness = Completeness {
            request_body: BodyState::Complete,
            response_body: BodyState::Missing,
        };
        copy_vendor_fields(body, &mut prompt.vendor);

        let mut issues = Vec::new();
        if prompt.model.is_none() {
            issues.push(ParseIssue::at(
                OPENAI_ADAPTER_ID,
                ParseIssueCode::MissingField,
                "/model",
            ));
        }
        match input.envelope.request.path.as_str() {
            "/v1/responses" => parse_responses(body, &mut prompt, &mut issues),
            "/v1/chat/completions" => parse_chat(body, &mut prompt, &mut issues),
            "/v1/completions" => parse_completions(body, &mut prompt, &mut issues),
            _ => {
                return Err(AdapterError::at(
                    ParseIssueCode::UnsupportedOperation,
                    "/request/path",
                ));
            }
        }
        prompt.tools = parse_tools(body.get("tools"), "/tools", &mut issues);
        Ok(AdapterOutput {
            prompt_ir: prompt,
            issues,
        })
    }
}

fn parse_responses(body: &Map<String, Value>, prompt: &mut PromptIr, issues: &mut Vec<ParseIssue>) {
    prompt.operation = Some("responses.create".to_owned());
    if let Some(instructions) = body.get("instructions") {
        let parts = parse_content(instructions, "/instructions", "instruction_0", issues);
        if !parts.is_empty() {
            prompt.instructions.push(Instruction {
                id: "instruction_0".to_owned(),
                role: InstructionRole::Developer,
                parts,
                evidence: observed("/instructions"),
            });
        }
    }

    match body.get("input") {
        Some(Value::String(value)) => prompt.messages.push(Message {
            id: "message_0".to_owned(),
            role: MessageRole::User,
            parts: vec![PromptPart::Text {
                id: "message_0_part_0".to_owned(),
                text: value.clone(),
                evidence: observed("/input"),
            }],
            evidence: observed("/input"),
        }),
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                parse_responses_item(item, index, prompt, issues);
            }
        }
        Some(value) => {
            prompt.messages.push(Message {
                id: "message_0".to_owned(),
                role: MessageRole::User,
                parts: parse_content(value, "/input", "message_0", issues),
                evidence: observed("/input"),
            });
        }
        None => issues.push(ParseIssue::at(
            OPENAI_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/input",
        )),
    }
}

fn parse_responses_item(
    item: &Value,
    index: usize,
    prompt: &mut PromptIr,
    issues: &mut Vec<ParseIssue>,
) {
    let pointer = format!("/input/{index}");
    let id = format!("message_{index}");
    let Some(object) = item.as_object() else {
        prompt.messages.push(Message {
            id: id.clone(),
            role: MessageRole::User,
            parts: parse_content(item, &pointer, &id, issues),
            evidence: observed(pointer),
        });
        return;
    };
    let item_type = object.get("type").and_then(Value::as_str);
    match item_type {
        Some("function_call") => {
            let tool_use_id = object
                .get("call_id")
                .and_then(Value::as_str)
                .unwrap_or(id.as_str())
                .to_owned();
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown_tool")
                .to_owned();
            let input = object
                .get("arguments")
                .map(parse_json_string)
                .unwrap_or(Value::Null);
            prompt.messages.push(Message {
                id: id.clone(),
                role: MessageRole::Assistant,
                parts: vec![PromptPart::ToolUse {
                    id: tool_use_id,
                    name,
                    input,
                    evidence: observed(&pointer),
                }],
                evidence: observed(pointer),
            });
        }
        Some("function_call_output") => {
            let tool_use_id = object
                .get("call_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown_call")
                .to_owned();
            let value = object.get("output").cloned().unwrap_or(Value::Null);
            prompt.messages.push(Message {
                id: id.clone(),
                role: MessageRole::Tool,
                parts: vec![PromptPart::ToolResult {
                    id: format!("{id}_tool_result"),
                    tool_use_id,
                    value,
                    evidence: observed(&pointer),
                }],
                evidence: observed(pointer),
            });
        }
        _ => {
            let role = object
                .get("role")
                .and_then(Value::as_str)
                .map(parse_message_role)
                .unwrap_or(MessageRole::User);
            let content = object.get("content").unwrap_or(item);
            prompt.messages.push(Message {
                id: id.clone(),
                role,
                parts: parse_content(content, &format!("{pointer}/content"), &id, issues),
                evidence: observed(pointer),
            });
        }
    }
}

fn parse_chat(body: &Map<String, Value>, prompt: &mut PromptIr, issues: &mut Vec<ParseIssue>) {
    prompt.operation = Some("chat.completions.create".to_owned());
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        issues.push(ParseIssue::at(
            OPENAI_ADAPTER_ID,
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
            OPENAI_ADAPTER_ID,
            ParseIssueCode::InvalidField,
            pointer,
        ));
        return;
    };
    let role = object
        .get("role")
        .and_then(Value::as_str)
        .map(parse_message_role)
        .unwrap_or(MessageRole::Unknown);
    if role == MessageRole::Unknown {
        issues.push(ParseIssue::at(
            OPENAI_ADAPTER_ID,
            ParseIssueCode::InvalidField,
            format!("{pointer}/role"),
        ));
    }

    if matches!(role, MessageRole::System | MessageRole::Developer) {
        let instruction_role = if role == MessageRole::System {
            InstructionRole::System
        } else {
            InstructionRole::Developer
        };
        let id = format!("instruction_{index}");
        let content = object.get("content").unwrap_or(&Value::Null);
        prompt.instructions.push(Instruction {
            id: id.clone(),
            role: instruction_role,
            parts: parse_content(content, &format!("{pointer}/content"), &id, issues),
            evidence: observed(pointer),
        });
        return;
    }

    let id = format!("message_{index}");
    let mut parts = if role == MessageRole::Tool {
        let tool_use_id = object
            .get("tool_call_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown_call")
            .to_owned();
        vec![PromptPart::ToolResult {
            id: format!("{id}_tool_result"),
            tool_use_id,
            value: object.get("content").cloned().unwrap_or(Value::Null),
            evidence: observed(format!("{pointer}/content")),
        }]
    } else {
        parse_content(
            object.get("content").unwrap_or(&Value::Null),
            &format!("{pointer}/content"),
            &id,
            issues,
        )
    };
    if let Some(tool_calls) = object.get("tool_calls").and_then(Value::as_array) {
        for (tool_index, tool_call) in tool_calls.iter().enumerate() {
            parts.push(parse_tool_call(tool_call, index, tool_index));
        }
    }
    prompt.messages.push(Message {
        id,
        role,
        parts,
        evidence: observed(pointer),
    });
}

fn parse_tool_call(value: &Value, message_index: usize, tool_index: usize) -> PromptPart {
    let pointer = format!("/messages/{message_index}/tool_calls/{tool_index}");
    let function = value
        .get("function")
        .and_then(Value::as_object)
        .or_else(|| value.as_object());
    let name = function
        .and_then(|function| function.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown_tool")
        .to_owned();
    let input = function
        .and_then(|function| function.get("arguments"))
        .map(parse_json_string)
        .unwrap_or(Value::Null);
    PromptPart::ToolUse {
        id: value.get("id").and_then(Value::as_str).map_or_else(
            || format!("message_{message_index}_tool_{tool_index}"),
            str::to_owned,
        ),
        name,
        input,
        evidence: observed(pointer),
    }
}

fn parse_completions(
    body: &Map<String, Value>,
    prompt: &mut PromptIr,
    issues: &mut Vec<ParseIssue>,
) {
    prompt.operation = Some("completions.create".to_owned());
    let Some(value) = body.get("prompt") else {
        issues.push(ParseIssue::at(
            OPENAI_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/prompt",
        ));
        return;
    };
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let id = format!("message_{index}");
                prompt.messages.push(Message {
                    id: id.clone(),
                    role: MessageRole::User,
                    parts: parse_content(value, &format!("/prompt/{index}"), &id, issues),
                    evidence: observed(format!("/prompt/{index}")),
                });
            }
        }
        _ => prompt.messages.push(Message {
            id: "message_0".to_owned(),
            role: MessageRole::User,
            parts: parse_content(value, "/prompt", "message_0", issues),
            evidence: observed("/prompt"),
        }),
    }
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
                parse_content_item(
                    value,
                    &format!("{pointer}/{index}"),
                    &format!("{id_prefix}_part_{index}"),
                    issues,
                )
            })
            .collect(),
        _ => vec![parse_content_item(
            value,
            pointer,
            &format!("{id_prefix}_part_0"),
            issues,
        )],
    }
}

fn parse_content_item(
    value: &Value,
    pointer: &str,
    id: &str,
    issues: &mut Vec<ParseIssue>,
) -> PromptPart {
    let Some(object) = value.as_object() else {
        return PromptPart::Json {
            id: id.to_owned(),
            value: value.clone(),
            evidence: observed(pointer),
        };
    };
    let item_type = object.get("type").and_then(Value::as_str);
    match item_type {
        Some("text" | "input_text" | "output_text") | None if object.get("text").is_some() => {
            PromptPart::Text {
                id: id.to_owned(),
                text: object
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                evidence: observed(pointer),
            }
        }
        Some("image_url" | "input_image") => PromptPart::ImageRef {
            id: id.to_owned(),
            location: media_location(object, &["image_url", "url", "file_id"]),
            media_type: object
                .get("media_type")
                .and_then(Value::as_str)
                .map(str::to_owned),
            evidence: observed(pointer),
        },
        Some("input_file" | "file") => PromptPart::FileRef {
            id: id.to_owned(),
            location: media_location(object, &["file_id", "file_url", "filename"]),
            media_type: object
                .get("media_type")
                .and_then(Value::as_str)
                .map(str::to_owned),
            evidence: observed(pointer),
        },
        Some("input_audio" | "audio") => PromptPart::AudioRef {
            id: id.to_owned(),
            location: media_location(object, &["audio_url", "url", "id"]),
            media_type: object
                .get("format")
                .and_then(Value::as_str)
                .map(str::to_owned),
            evidence: observed(pointer),
        },
        _ => {
            issues.push(ParseIssue::at(
                OPENAI_ADAPTER_ID,
                ParseIssueCode::UnsupportedContent,
                pointer,
            ));
            PromptPart::Unknown {
                id: id.to_owned(),
                value: value.clone(),
                evidence: observed(pointer),
            }
        }
    }
}

fn parse_tools(
    value: Option<&Value>,
    pointer: &str,
    issues: &mut Vec<ParseIssue>,
) -> Vec<ToolDefinition> {
    let Some(tools) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    tools
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            let tool_pointer = format!("{pointer}/{index}");
            let object = value.as_object()?;
            let function = object
                .get("function")
                .and_then(Value::as_object)
                .unwrap_or(object);
            let Some(name) = function.get("name").and_then(Value::as_str) else {
                issues.push(ParseIssue::at(
                    OPENAI_ADAPTER_ID,
                    ParseIssueCode::MissingField,
                    format!("{tool_pointer}/name"),
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
                    .or_else(|| function.get("input_schema"))
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                evidence: observed(tool_pointer),
            })
        })
        .collect()
}

fn parse_generation(body: &Map<String, Value>) -> GenerationOptions {
    let stop = match body.get("stop") {
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    let mut extra = BTreeMap::new();
    for key in ["frequency_penalty", "presence_penalty", "seed"] {
        if let Some(value) = body.get(key) {
            extra.insert(key.to_owned(), value.clone());
        }
    }
    GenerationOptions {
        temperature: body.get("temperature").and_then(Value::as_f64),
        top_p: body.get("top_p").and_then(Value::as_f64),
        max_output_tokens: ["max_output_tokens", "max_completion_tokens", "max_tokens"]
            .iter()
            .find_map(|key| body.get(*key).and_then(Value::as_u64)),
        stop,
        extra,
    }
}

fn copy_vendor_fields(body: &Map<String, Value>, vendor: &mut BTreeMap<String, Value>) {
    for key in [
        "stream",
        "parallel_tool_calls",
        "tool_choice",
        "response_format",
    ] {
        if let Some(value) = body.get(key) {
            vendor.insert(key.to_owned(), value.clone());
        }
    }
}

fn parse_message_role(role: &str) -> MessageRole {
    match role {
        "system" => MessageRole::System,
        "developer" => MessageRole::Developer,
        "user" => MessageRole::User,
        "assistant" => MessageRole::Assistant,
        "tool" => MessageRole::Tool,
        _ => MessageRole::Unknown,
    }
}

fn media_location(object: &Map<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| {
            object.get(*key).and_then(|value| match value {
                Value::String(value) => Some(value.clone()),
                Value::Object(value) => value.get("url").and_then(Value::as_str).map(str::to_owned),
                _ => None,
            })
        })
        .unwrap_or_else(|| "unknown media location".to_owned())
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
