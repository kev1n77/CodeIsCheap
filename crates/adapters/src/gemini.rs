use std::collections::BTreeMap;

use codeischeap_capture_ipc::CapturedBodyState;
use codeischeap_prompt_ir::{
    BodyState, Completeness, Evidence, EvidenceSource, GenerationOptions, Instruction,
    InstructionRole, Message, MessageRole, PromptIr, PromptPart, ToolDefinition,
};
use serde_json::{Map, Value, json};

use crate::gemini_response::parse_gemini_response;
use crate::model::{
    AdapterError, AdapterInput, AdapterOutput, ParseIssue, ParseIssueCode, PromptAdapter,
};

pub const GEMINI_ADAPTER_ID: &str = "gemini/v0.1";

#[derive(Debug, Clone, Copy, Default)]
pub struct GeminiAdapter;

impl PromptAdapter for GeminiAdapter {
    fn id(&self) -> &'static str {
        GEMINI_ADAPTER_ID
    }

    fn detect(&self, input: AdapterInput<'_>) -> Option<f32> {
        (input.target_id == "gemini" && parse_path(&input.envelope.request.path).is_some())
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
        let path = parse_path(&input.envelope.request.path).ok_or_else(|| {
            AdapterError::at(ParseIssueCode::UnsupportedOperation, "/request/path")
        })?;

        let mut prompt = PromptIr::new(&input.envelope.capture_id, "gemini");
        prompt.provider.host = Some(input.envelope.request.host.clone());
        prompt.provider.confidence = Some(1.0);
        prompt.operation = Some(path.operation.to_owned());
        prompt.model = Some(path.model.to_owned());
        prompt.generation = parse_generation(body.get("generationConfig"));
        prompt.completeness = Completeness {
            request_body: BodyState::Complete,
            response_body: BodyState::Missing,
        };
        prompt.vendor.insert(
            "api_version".to_owned(),
            Value::String(path.api_version.to_owned()),
        );
        if path.streaming {
            prompt.vendor.insert("stream".to_owned(), Value::Bool(true));
        }
        copy_vendor_fields(body, &mut prompt.vendor);

        let mut issues = Vec::new();
        parse_system_instruction(body.get("systemInstruction"), &mut prompt, &mut issues);
        parse_contents(body.get("contents"), &mut prompt, &mut issues);
        prompt.tools = parse_tools(body.get("tools"), &mut issues);
        parse_gemini_response(
            input.envelope.outcome.as_ref(),
            path.streaming,
            &mut prompt,
            &mut issues,
        );

        Ok(AdapterOutput {
            prompt_ir: prompt,
            issues,
        })
    }
}

struct GeminiPath<'a> {
    api_version: &'a str,
    model: &'a str,
    operation: &'static str,
    streaming: bool,
}

fn parse_path(path: &str) -> Option<GeminiPath<'_>> {
    let path = path.strip_prefix('/')?;
    let (api_version, rest) = path.split_once("/models/")?;
    if !matches!(api_version, "v1" | "v1beta") {
        return None;
    }
    let (model, method) = rest.rsplit_once(':')?;
    if model.is_empty() || model.contains('/') {
        return None;
    }
    let (operation, streaming) = match method {
        "generateContent" => ("models.generate_content", false),
        "streamGenerateContent" => ("models.stream_generate_content", true),
        _ => return None,
    };
    Some(GeminiPath {
        api_version,
        model,
        operation,
        streaming,
    })
}

fn parse_system_instruction(
    value: Option<&Value>,
    prompt: &mut PromptIr,
    issues: &mut Vec<ParseIssue>,
) {
    let Some(value) = value else {
        return;
    };
    let Some(parts_value) = value.get("parts") else {
        issues.push(ParseIssue::at(
            GEMINI_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/systemInstruction/parts",
        ));
        return;
    };
    let parts = parse_parts(
        parts_value,
        "/systemInstruction/parts",
        "instruction_0",
        issues,
    );
    prompt.instructions.push(Instruction {
        id: "instruction_0".to_owned(),
        role: InstructionRole::System,
        parts,
        evidence: observed("/systemInstruction"),
    });
}

fn parse_contents(value: Option<&Value>, prompt: &mut PromptIr, issues: &mut Vec<ParseIssue>) {
    let Some(contents) = value.and_then(Value::as_array) else {
        issues.push(ParseIssue::at(
            GEMINI_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/contents",
        ));
        return;
    };
    for (index, value) in contents.iter().enumerate() {
        let pointer = format!("/contents/{index}");
        let Some(object) = value.as_object() else {
            issues.push(ParseIssue::at(
                GEMINI_ADAPTER_ID,
                ParseIssueCode::InvalidField,
                pointer,
            ));
            continue;
        };
        let parts_value = object.get("parts").unwrap_or(&Value::Null);
        let role = match object.get("role").and_then(Value::as_str) {
            Some("model") => MessageRole::Assistant,
            Some("function") => MessageRole::Tool,
            Some("user") | None if all_function_responses(parts_value) => MessageRole::Tool,
            Some("user") | None => MessageRole::User,
            Some("system") => MessageRole::System,
            _ => {
                issues.push(ParseIssue::at(
                    GEMINI_ADAPTER_ID,
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
            parts: parse_parts(parts_value, &format!("{pointer}/parts"), &id, issues),
            evidence: observed(pointer),
        });
    }
}

fn all_function_responses(parts: &Value) -> bool {
    let Some(parts) = parts.as_array() else {
        return false;
    };
    !parts.is_empty()
        && parts.iter().all(|part| {
            part.get("functionResponse")
                .or_else(|| part.get("function_response"))
                .is_some()
        })
}

fn parse_parts(
    value: &Value,
    pointer: &str,
    id_prefix: &str,
    issues: &mut Vec<ParseIssue>,
) -> Vec<PromptPart> {
    match value {
        Value::Array(parts) => parts
            .iter()
            .enumerate()
            .map(|(index, part)| {
                parse_part(
                    part,
                    &format!("{pointer}/{index}"),
                    &format!("{id_prefix}_part_{index}"),
                    issues,
                )
            })
            .collect(),
        Value::Null => Vec::new(),
        _ => vec![parse_part(
            value,
            pointer,
            &format!("{id_prefix}_part_0"),
            issues,
        )],
    }
}

fn parse_part(
    value: &Value,
    pointer: &str,
    fallback_id: &str,
    issues: &mut Vec<ParseIssue>,
) -> PromptPart {
    parse_part_with_evidence(value, fallback_id, observed(pointer), pointer, issues)
}

pub(crate) fn parse_part_with_evidence(
    value: &Value,
    fallback_id: &str,
    evidence: Evidence,
    issue_path: &str,
    issues: &mut Vec<ParseIssue>,
) -> PromptPart {
    let Some(object) = value.as_object() else {
        return PromptPart::Json {
            id: fallback_id.to_owned(),
            value: value.clone(),
            evidence,
        };
    };
    if let Some(text) = object.get("text").and_then(Value::as_str) {
        return PromptPart::Text {
            id: fallback_id.to_owned(),
            text: text.to_owned(),
            evidence,
        };
    }
    if let Some(data) = object
        .get("inlineData")
        .or_else(|| object.get("inline_data"))
        .and_then(Value::as_object)
    {
        return media_part(data, "inline:base64", fallback_id, evidence);
    }
    if let Some(data) = object
        .get("fileData")
        .or_else(|| object.get("file_data"))
        .and_then(Value::as_object)
    {
        let location =
            string_field(data, &["fileUri", "file_uri"]).unwrap_or("unknown media location");
        return media_part(data, location, fallback_id, evidence);
    }
    if let Some(call) = object
        .get("functionCall")
        .or_else(|| object.get("function_call"))
        .and_then(Value::as_object)
    {
        let name = call
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown_tool")
            .to_owned();
        if call.get("name").and_then(Value::as_str).is_none() {
            issues.push(ParseIssue::at(
                GEMINI_ADAPTER_ID,
                ParseIssueCode::MissingField,
                format!("{issue_path}/functionCall/name"),
            ));
        }
        return PromptPart::ToolUse {
            id: call
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .unwrap_or(fallback_id)
                .to_owned(),
            name,
            input: call.get("args").cloned().unwrap_or_else(|| json!({})),
            evidence,
        };
    }
    if let Some(response) = object
        .get("functionResponse")
        .or_else(|| object.get("function_response"))
        .and_then(Value::as_object)
    {
        let name = response
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("unknown_tool");
        return PromptPart::ToolResult {
            id: fallback_id.to_owned(),
            tool_use_id: response
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map_or_else(|| format!("function:{name}"), str::to_owned),
            value: response
                .get("response")
                .cloned()
                .unwrap_or_else(|| json!({})),
            evidence,
        };
    }
    if object.contains_key("executableCode")
        || object.contains_key("codeExecutionResult")
        || object.contains_key("thoughtSignature")
    {
        return PromptPart::Json {
            id: fallback_id.to_owned(),
            value: value.clone(),
            evidence,
        };
    }

    issues.push(ParseIssue::at(
        GEMINI_ADAPTER_ID,
        ParseIssueCode::UnsupportedContent,
        issue_path,
    ));
    PromptPart::Unknown {
        id: fallback_id.to_owned(),
        value: value.clone(),
        evidence,
    }
}

fn media_part(
    data: &Map<String, Value>,
    location: &str,
    id: &str,
    evidence: Evidence,
) -> PromptPart {
    let media_type = string_field(data, &["mimeType", "mime_type"]).map(str::to_owned);
    match media_type.as_deref() {
        Some(value) if value.starts_with("image/") => PromptPart::ImageRef {
            id: id.to_owned(),
            location: location.to_owned(),
            media_type,
            evidence,
        },
        Some(value) if value.starts_with("audio/") => PromptPart::AudioRef {
            id: id.to_owned(),
            location: location.to_owned(),
            media_type,
            evidence,
        },
        _ => PromptPart::FileRef {
            id: id.to_owned(),
            location: location.to_owned(),
            media_type,
            evidence,
        },
    }
}

fn parse_tools(value: Option<&Value>, issues: &mut Vec<ParseIssue>) -> Vec<ToolDefinition> {
    let Some(tools) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut definitions = Vec::new();
    for (tool_index, tool) in tools.iter().enumerate() {
        let Some(declarations) = tool.get("functionDeclarations").and_then(Value::as_array) else {
            issues.push(ParseIssue::at(
                GEMINI_ADAPTER_ID,
                ParseIssueCode::UnsupportedContent,
                format!("/tools/{tool_index}"),
            ));
            continue;
        };
        for (function_index, declaration) in declarations.iter().enumerate() {
            let pointer = format!("/tools/{tool_index}/functionDeclarations/{function_index}");
            let Some(object) = declaration.as_object() else {
                issues.push(ParseIssue::at(
                    GEMINI_ADAPTER_ID,
                    ParseIssueCode::InvalidField,
                    pointer,
                ));
                continue;
            };
            let Some(name) = object.get("name").and_then(Value::as_str) else {
                issues.push(ParseIssue::at(
                    GEMINI_ADAPTER_ID,
                    ParseIssueCode::MissingField,
                    format!("{pointer}/name"),
                ));
                continue;
            };
            definitions.push(ToolDefinition {
                id: format!("tool_{tool_index}_function_{function_index}"),
                name: name.to_owned(),
                description: object
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                input_schema: object
                    .get("parametersJsonSchema")
                    .or_else(|| object.get("parameters"))
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                evidence: observed(pointer),
            });
        }
    }
    definitions
}

fn parse_generation(value: Option<&Value>) -> GenerationOptions {
    let Some(config) = value.and_then(Value::as_object) else {
        return GenerationOptions::default();
    };
    let stop = config
        .get("stopSequences")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut extra = BTreeMap::new();
    for key in [
        "topK",
        "candidateCount",
        "seed",
        "responseMimeType",
        "responseSchema",
        "responseJsonSchema",
        "presencePenalty",
        "frequencyPenalty",
        "thinkingConfig",
        "mediaResolution",
        "speechConfig",
    ] {
        if let Some(value) = config.get(key) {
            extra.insert(key.to_owned(), value.clone());
        }
    }
    GenerationOptions {
        temperature: config.get("temperature").and_then(Value::as_f64),
        top_p: config.get("topP").and_then(Value::as_f64),
        max_output_tokens: config.get("maxOutputTokens").and_then(Value::as_u64),
        stop,
        extra,
    }
}

fn copy_vendor_fields(body: &Map<String, Value>, vendor: &mut BTreeMap<String, Value>) {
    for key in ["cachedContent", "safetySettings", "toolConfig", "labels"] {
        if let Some(value) = body.get(key) {
            vendor.insert(key.to_owned(), value.clone());
        }
    }
}

fn string_field<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
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
    fn gemini_paths_extract_version_model_and_operation() {
        let path = parse_path("/v1beta/models/gemini-2.5-pro:streamGenerateContent")
            .expect("path must match");
        assert_eq!(path.api_version, "v1beta");
        assert_eq!(path.model, "gemini-2.5-pro");
        assert_eq!(path.operation, "models.stream_generate_content");
        assert!(path.streaming);
        assert!(parse_path("/v1beta/models/gemini-2.5-pro:embedContent").is_none());
    }
}
