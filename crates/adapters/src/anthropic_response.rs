use std::collections::{BTreeMap, HashMap};

use codeischeap_capture_ipc::{
    CaptureOutcome, CapturedBodyState, CapturedResponse, ResponseCompleteness,
};
use codeischeap_prompt_ir::{
    BodyState, Evidence, EvidenceSource, MessageRole, PromptIr, PromptPart, ResponseEvent,
    ResponseTrace,
};
use serde_json::{Map, Value, json};

use crate::anthropic::ANTHROPIC_ADAPTER_ID;
use crate::model::{ParseIssue, ParseIssueCode};

pub(crate) fn parse_anthropic_response(
    outcome: Option<&CaptureOutcome>,
    request_path: &str,
    prompt: &mut PromptIr,
    issues: &mut Vec<ParseIssue>,
) {
    let Some(CaptureOutcome::Response(response)) = outcome else {
        prompt.completeness.response_body = BodyState::Missing;
        return;
    };
    let captured_state = response_body_state(response);
    prompt.completeness.response_body = captured_state;

    match response.body.state {
        CapturedBodyState::Json => {
            let Some(body) = response.body.content.as_ref().and_then(Value::as_object) else {
                issues.push(ParseIssue::at(
                    ANTHROPIC_ADAPTER_ID,
                    ParseIssueCode::InvalidBody,
                    "/outcome/result/body/content",
                ));
                prompt.completeness.response_body = BodyState::Unsupported;
                return;
            };
            prompt.response = Some(parse_json_response(body, request_path, issues));
        }
        CapturedBodyState::Text => {
            let Some(text) = response.body.content.as_ref().and_then(Value::as_str) else {
                issues.push(ParseIssue::at(
                    ANTHROPIC_ADAPTER_ID,
                    ParseIssueCode::InvalidBody,
                    "/outcome/result/body/content",
                ));
                prompt.completeness.response_body = BodyState::Unsupported;
                return;
            };
            let parsed = parse_sse_response(text, issues);
            let Some(trace) = parsed.trace else {
                issues.push(ParseIssue::at(
                    ANTHROPIC_ADAPTER_ID,
                    ParseIssueCode::InvalidBody,
                    "/response/events",
                ));
                if captured_state == BodyState::Complete {
                    prompt.completeness.response_body = BodyState::Unsupported;
                }
                return;
            };
            if captured_state == BodyState::Complete && !parsed.saw_terminal_event {
                prompt.completeness.response_body = BodyState::Partial;
                issues.push(ParseIssue::at(
                    ANTHROPIC_ADAPTER_ID,
                    ParseIssueCode::MissingField,
                    "/response/events/message_stop",
                ));
            }
            prompt.response = Some(trace);
        }
        CapturedBodyState::Empty => {
            prompt.completeness.response_body = BodyState::Complete;
        }
        CapturedBodyState::Truncated => {
            prompt.completeness.response_body = BodyState::Partial;
        }
        CapturedBodyState::InvalidJson
        | CapturedBodyState::InvalidUtf8
        | CapturedBodyState::OmittedUnsupportedContentType => {
            prompt.completeness.response_body = BodyState::Unsupported;
        }
    }
}

fn response_body_state(response: &CapturedResponse) -> BodyState {
    if response.completeness != ResponseCompleteness::Complete {
        return BodyState::Partial;
    }
    match response.body.state {
        CapturedBodyState::Empty | CapturedBodyState::Json | CapturedBodyState::Text => {
            BodyState::Complete
        }
        CapturedBodyState::Truncated => BodyState::Partial,
        CapturedBodyState::InvalidJson
        | CapturedBodyState::InvalidUtf8
        | CapturedBodyState::OmittedUnsupportedContentType => BodyState::Unsupported,
    }
}

fn parse_json_response(
    body: &Map<String, Value>,
    request_path: &str,
    issues: &mut Vec<ParseIssue>,
) -> ResponseTrace {
    let evidence = json_evidence("/outcome/result/body/content");
    if body.get("type").and_then(Value::as_str) == Some("error") || body.contains_key("error") {
        return ResponseTrace {
            id: body
                .get("request_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            model: None,
            role: MessageRole::Unknown,
            parts: Vec::new(),
            stop_reason: None,
            stop_sequence: None,
            usage: BTreeMap::new(),
            error: body
                .get("error")
                .cloned()
                .or_else(|| Some(Value::Object(body.clone()))),
            events: Vec::new(),
            evidence,
        };
    }

    if request_path == "/v1/complete" {
        let completion = body
            .get("completion")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if completion.is_empty() {
            issues.push(ParseIssue::at(
                ANTHROPIC_ADAPTER_ID,
                ParseIssueCode::MissingField,
                "/outcome/result/body/content/completion",
            ));
        }
        return ResponseTrace {
            id: body.get("id").and_then(Value::as_str).map(str::to_owned),
            model: body.get("model").and_then(Value::as_str).map(str::to_owned),
            role: MessageRole::Assistant,
            parts: vec![PromptPart::Text {
                id: "response_part_0".to_owned(),
                text: completion.to_owned(),
                evidence: json_evidence("/outcome/result/body/content/completion"),
            }],
            stop_reason: body
                .get("stop_reason")
                .and_then(Value::as_str)
                .map(str::to_owned),
            stop_sequence: body.get("stop").and_then(Value::as_str).map(str::to_owned),
            usage: BTreeMap::new(),
            error: None,
            events: Vec::new(),
            evidence,
        };
    }

    let parts = body
        .get("content")
        .and_then(Value::as_array)
        .map(|content| {
            content
                .iter()
                .enumerate()
                .map(|(index, block)| {
                    response_json_block(
                        block,
                        index,
                        &format!("/outcome/result/body/content/content/{index}"),
                        issues,
                    )
                })
                .collect()
        })
        .unwrap_or_else(|| {
            issues.push(ParseIssue::at(
                ANTHROPIC_ADAPTER_ID,
                ParseIssueCode::MissingField,
                "/outcome/result/body/content/content",
            ));
            Vec::new()
        });
    ResponseTrace {
        id: body.get("id").and_then(Value::as_str).map(str::to_owned),
        model: body.get("model").and_then(Value::as_str).map(str::to_owned),
        role: message_role(body.get("role").and_then(Value::as_str)),
        parts,
        stop_reason: body
            .get("stop_reason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        stop_sequence: body
            .get("stop_sequence")
            .and_then(Value::as_str)
            .map(str::to_owned),
        usage: value_map(body.get("usage")),
        error: None,
        events: Vec::new(),
        evidence,
    }
}

fn response_json_block(
    value: &Value,
    index: usize,
    pointer: &str,
    issues: &mut Vec<ParseIssue>,
) -> PromptPart {
    let id = format!("response_part_{index}");
    let evidence = json_evidence(pointer);
    let Some(object) = value.as_object() else {
        return PromptPart::Unknown {
            id,
            value: value.clone(),
            evidence,
        };
    };
    match object.get("type").and_then(Value::as_str) {
        Some("text") => PromptPart::Text {
            id,
            text: object
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            evidence,
        },
        Some("tool_use" | "server_tool_use") => PromptPart::ToolUse {
            id: object
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .unwrap_or(&id)
                .to_owned(),
            name: object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown_tool")
                .to_owned(),
            input: object.get("input").cloned().unwrap_or_else(|| json!({})),
            evidence,
        },
        Some("thinking" | "redacted_thinking") => PromptPart::Json {
            id,
            value: value.clone(),
            evidence,
        },
        _ => {
            issues.push(ParseIssue::at(
                ANTHROPIC_ADAPTER_ID,
                ParseIssueCode::UnsupportedContent,
                pointer,
            ));
            PromptPart::Unknown {
                id,
                value: value.clone(),
                evidence,
            }
        }
    }
}

struct ParsedStream {
    trace: Option<ResponseTrace>,
    saw_terminal_event: bool,
}

#[derive(Default)]
struct TraceBuilder {
    id: Option<String>,
    model: Option<String>,
    role: Option<MessageRole>,
    blocks: HashMap<u64, BlockAccumulator>,
    stop_reason: Option<String>,
    stop_sequence: Option<String>,
    usage: BTreeMap<String, Value>,
    error: Option<Value>,
    events: Vec<ResponseEvent>,
    first_event: Option<u64>,
    saw_message_stop: bool,
    saw_legacy_stop: bool,
}

enum BlockAccumulator {
    Text {
        start_event: u64,
        text: String,
    },
    ToolUse {
        start_event: u64,
        id: String,
        name: String,
        initial_input: Value,
        partial_json: String,
    },
    Thinking {
        start_event: u64,
        thinking: String,
        signature: String,
    },
    Unknown {
        start_event: u64,
        value: Value,
    },
}

fn parse_sse_response(text: &str, issues: &mut Vec<ParseIssue>) -> ParsedStream {
    let frames = parse_sse_frames(text);
    if frames.is_empty() {
        return ParsedStream {
            trace: None,
            saw_terminal_event: false,
        };
    }
    let mut builder = TraceBuilder::default();
    for frame in frames {
        let pointer = format!("/response/events/{}", frame.index);
        let data: Value = match serde_json::from_str(&frame.data) {
            Ok(data) => data,
            Err(_) => {
                issues.push(ParseIssue::at(
                    ANTHROPIC_ADAPTER_ID,
                    ParseIssueCode::InvalidStreamEvent,
                    pointer,
                ));
                continue;
            }
        };
        let data_type = data.get("type").and_then(Value::as_str);
        let kind = data_type.or(frame.event.as_deref()).unwrap_or("message");
        if let (Some(event), Some(data_type)) = (frame.event.as_deref(), data_type)
            && event != data_type
        {
            issues.push(ParseIssue::at(
                ANTHROPIC_ADAPTER_ID,
                ParseIssueCode::InvalidStreamEvent,
                format!("{pointer}/type"),
            ));
        }
        let content_index = data.get("index").and_then(Value::as_u64);
        let delta_kind = data
            .get("delta")
            .and_then(|delta| delta.get("type"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        builder.first_event.get_or_insert(frame.index);
        builder.events.push(ResponseEvent {
            index: frame.index,
            kind: kind.to_owned(),
            content_index,
            delta_kind,
            evidence: stream_evidence(frame.index),
        });
        apply_stream_event(&mut builder, kind, &data, frame.index, issues);
    }
    if builder.events.is_empty() {
        return ParsedStream {
            trace: None,
            saw_terminal_event: false,
        };
    }
    let first_event = builder.first_event.unwrap_or(0);
    let mut block_indexes = builder.blocks.keys().copied().collect::<Vec<_>>();
    block_indexes.sort_unstable();
    let parts = block_indexes
        .into_iter()
        .filter_map(|index| {
            let block = builder.blocks.remove(&index)?;
            Some(block.into_part(index, issues))
        })
        .collect();
    ParsedStream {
        saw_terminal_event: builder.saw_message_stop
            || builder.saw_legacy_stop
            || builder.error.is_some(),
        trace: Some(ResponseTrace {
            id: builder.id,
            model: builder.model,
            role: builder.role.unwrap_or(MessageRole::Assistant),
            parts,
            stop_reason: builder.stop_reason,
            stop_sequence: builder.stop_sequence,
            usage: builder.usage,
            error: builder.error,
            events: builder.events,
            evidence: stream_evidence(first_event),
        }),
    }
}

fn apply_stream_event(
    builder: &mut TraceBuilder,
    kind: &str,
    data: &Value,
    event_index: u64,
    issues: &mut Vec<ParseIssue>,
) {
    match kind {
        "message_start" => {
            let message = data.get("message").unwrap_or(&Value::Null);
            builder.id = message.get("id").and_then(Value::as_str).map(str::to_owned);
            builder.model = message
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_owned);
            builder.role = Some(message_role(message.get("role").and_then(Value::as_str)));
            merge_value_map(&mut builder.usage, message.get("usage"));
        }
        "content_block_start" => {
            let Some(index) = data.get("index").and_then(Value::as_u64) else {
                issues.push(stream_issue(event_index, "index"));
                return;
            };
            let block = data.get("content_block").cloned().unwrap_or(Value::Null);
            builder
                .blocks
                .insert(index, BlockAccumulator::from_start(block, event_index));
        }
        "content_block_delta" => {
            let Some(index) = data.get("index").and_then(Value::as_u64) else {
                issues.push(stream_issue(event_index, "index"));
                return;
            };
            let Some(block) = builder.blocks.get_mut(&index) else {
                issues.push(stream_issue(event_index, "content_block_start"));
                return;
            };
            block.apply_delta(
                data.get("delta").unwrap_or(&Value::Null),
                event_index,
                issues,
            );
        }
        "message_delta" => {
            let delta = data.get("delta").unwrap_or(&Value::Null);
            builder.stop_reason = delta
                .get("stop_reason")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| builder.stop_reason.take());
            builder.stop_sequence = delta
                .get("stop_sequence")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| builder.stop_sequence.take());
            merge_value_map(&mut builder.usage, data.get("usage"));
        }
        "message_stop" => builder.saw_message_stop = true,
        "error" => builder.error = data.get("error").cloned().or_else(|| Some(data.clone())),
        "completion" => {
            let block = builder
                .blocks
                .entry(0)
                .or_insert_with(|| BlockAccumulator::Text {
                    start_event: event_index,
                    text: String::new(),
                });
            if let BlockAccumulator::Text { text, .. } = block
                && let Some(delta) = data.get("completion").and_then(Value::as_str)
            {
                text.push_str(delta);
            }
            builder.model = data.get("model").and_then(Value::as_str).map(str::to_owned);
            if let Some(reason) = data.get("stop_reason").and_then(Value::as_str) {
                builder.stop_reason = Some(reason.to_owned());
                builder.saw_legacy_stop = true;
            }
        }
        "content_block_stop" | "ping" => {}
        _ => {}
    }
}

impl BlockAccumulator {
    fn from_start(value: Value, event_index: u64) -> Self {
        match value.get("type").and_then(Value::as_str) {
            Some("text") => Self::Text {
                start_event: event_index,
                text: value
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            },
            Some("tool_use" | "server_tool_use") => Self::ToolUse {
                start_event: event_index,
                id: value
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                name: value
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown_tool")
                    .to_owned(),
                initial_input: value.get("input").cloned().unwrap_or_else(|| json!({})),
                partial_json: String::new(),
            },
            Some("thinking") => Self::Thinking {
                start_event: event_index,
                thinking: value
                    .get("thinking")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                signature: value
                    .get("signature")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            },
            _ => Self::Unknown {
                start_event: event_index,
                value,
            },
        }
    }

    fn apply_delta(&mut self, delta: &Value, event_index: u64, issues: &mut Vec<ParseIssue>) {
        match (self, delta.get("type").and_then(Value::as_str)) {
            (Self::Text { text, .. }, Some("text_delta")) => text.push_str(
                delta
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ),
            (Self::ToolUse { partial_json, .. }, Some("input_json_delta")) => partial_json
                .push_str(
                    delta
                        .get("partial_json")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
            (Self::Thinking { thinking, .. }, Some("thinking_delta")) => thinking.push_str(
                delta
                    .get("thinking")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ),
            (Self::Thinking { signature, .. }, Some("signature_delta")) => signature.push_str(
                delta
                    .get("signature")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            ),
            (_, Some("citations_delta")) => {}
            _ => issues.push(stream_issue(event_index, "delta")),
        }
    }

    fn into_part(self, index: u64, issues: &mut Vec<ParseIssue>) -> PromptPart {
        let fallback_id = format!("response_part_{index}");
        match self {
            Self::Text { start_event, text } => PromptPart::Text {
                id: fallback_id,
                text,
                evidence: stream_evidence(start_event),
            },
            Self::ToolUse {
                start_event,
                id,
                name,
                initial_input,
                partial_json,
            } => {
                let input = if partial_json.is_empty() {
                    initial_input
                } else {
                    serde_json::from_str(&partial_json).unwrap_or_else(|_| {
                        issues.push(ParseIssue::at(
                            ANTHROPIC_ADAPTER_ID,
                            ParseIssueCode::InvalidField,
                            format!("/response/content/{index}/input"),
                        ));
                        json!({"partial_json": partial_json})
                    })
                };
                PromptPart::ToolUse {
                    id: if id.is_empty() { fallback_id } else { id },
                    name,
                    input,
                    evidence: stream_evidence(start_event),
                }
            }
            Self::Thinking {
                start_event,
                thinking,
                signature,
            } => PromptPart::Json {
                id: fallback_id,
                value: json!({
                    "type": "thinking",
                    "thinking": thinking,
                    "signature": signature,
                }),
                evidence: stream_evidence(start_event),
            },
            Self::Unknown { start_event, value } => PromptPart::Unknown {
                id: fallback_id,
                value,
                evidence: stream_evidence(start_event),
            },
        }
    }
}

struct SseFrame {
    index: u64,
    event: Option<String>,
    data: String,
}

fn parse_sse_frames(text: &str) -> Vec<SseFrame> {
    let mut frames = Vec::new();
    let mut event = None;
    let mut data = Vec::new();
    for raw_line in text.split('\n') {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            flush_frame(&mut frames, &mut event, &mut data);
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').map_or((line, ""), |(field, value)| {
            (field, value.strip_prefix(' ').unwrap_or(value))
        });
        match field {
            "event" => event = Some(value.to_owned()),
            "data" => data.push(value.to_owned()),
            _ => {}
        }
    }
    flush_frame(&mut frames, &mut event, &mut data);
    frames
}

fn flush_frame(frames: &mut Vec<SseFrame>, event: &mut Option<String>, data: &mut Vec<String>) {
    if data.is_empty() {
        *event = None;
        return;
    }
    let index = u64::try_from(frames.len()).unwrap_or(u64::MAX);
    frames.push(SseFrame {
        index,
        event: event.take(),
        data: std::mem::take(data).join("\n"),
    });
}

fn message_role(role: Option<&str>) -> MessageRole {
    match role {
        Some("assistant") => MessageRole::Assistant,
        Some("user") => MessageRole::User,
        Some("system") => MessageRole::System,
        _ => MessageRole::Unknown,
    }
}

fn value_map(value: Option<&Value>) -> BTreeMap<String, Value> {
    value
        .and_then(Value::as_object)
        .map(|object| {
            object
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn merge_value_map(target: &mut BTreeMap<String, Value>, value: Option<&Value>) {
    target.extend(value_map(value));
}

fn json_evidence(pointer: impl Into<String>) -> Evidence {
    Evidence::observed(EvidenceSource::JsonPointer {
        pointer: pointer.into(),
    })
}

fn stream_evidence(index: u64) -> Evidence {
    Evidence::observed(EvidenceSource::StreamEvent { index })
}

fn stream_issue(event_index: u64, field: &str) -> ParseIssue {
    ParseIssue::at(
        ANTHROPIC_ADAPTER_ID,
        ParseIssueCode::InvalidStreamEvent,
        format!("/response/events/{event_index}/{field}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_fields_and_multiline_data_are_framed() {
        let frames = parse_sse_frames(
            ": keepalive\r\nevent: ping\r\ndata: {\"type\":\r\ndata: \"ping\"}\r\n\r\n",
        );

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("ping"));
        assert_eq!(frames[0].data, "{\"type\":\n\"ping\"}");
    }
}
