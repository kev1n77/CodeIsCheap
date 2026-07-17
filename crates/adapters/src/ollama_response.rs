use std::collections::BTreeMap;

use codeischeap_capture_ipc::{
    CaptureOutcome, CapturedBodyState, CapturedResponse, ResponseCompleteness,
};
use codeischeap_prompt_ir::{
    BodyState, Evidence, EvidenceSource, MessageRole, PromptIr, PromptPart, ResponseEvent,
    ResponseTrace,
};
use serde_json::{Map, Value, json};

use crate::model::{ParseIssue, ParseIssueCode};
use crate::ollama::{OLLAMA_ADAPTER_ID, OllamaOperation, parse_tool_call_with_evidence};

pub(crate) fn parse_ollama_response(
    outcome: Option<&CaptureOutcome>,
    operation: OllamaOperation,
    streaming: bool,
    prompt: &mut PromptIr,
    issues: &mut Vec<ParseIssue>,
) {
    let Some(CaptureOutcome::Response(response)) = outcome else {
        return;
    };
    prompt.completeness.response_body = response_body_state(response);
    let terminal = match response.body.state {
        CapturedBodyState::Json => {
            let Some(body) = response.body.content.as_ref().and_then(Value::as_object) else {
                issues.push(ParseIssue::at(
                    OLLAMA_ADAPTER_ID,
                    ParseIssueCode::InvalidBody,
                    "/outcome/result/body/content",
                ));
                return;
            };
            let (trace, terminal) = parse_json_response(body, operation, issues);
            prompt.response = Some(trace);
            terminal
        }
        CapturedBodyState::Text if streaming => {
            let text = response
                .body
                .content
                .as_ref()
                .and_then(Value::as_str)
                .unwrap_or_default();
            let parsed = parse_ndjson_response(text, operation, issues);
            prompt.response = parsed.trace;
            parsed.terminal
        }
        CapturedBodyState::Empty => true,
        CapturedBodyState::Text
        | CapturedBodyState::InvalidJson
        | CapturedBodyState::InvalidUtf8
        | CapturedBodyState::Truncated
        | CapturedBodyState::OmittedUnsupportedContentType => false,
    };
    if prompt.completeness.response_body == BodyState::Complete && !terminal {
        prompt.completeness.response_body = BodyState::Partial;
        issues.push(ParseIssue::at(
            OLLAMA_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/response/events/done",
        ));
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
    operation: OllamaOperation,
    issues: &mut Vec<ParseIssue>,
) -> (ResponseTrace, bool) {
    let root = "/outcome/result/body/content";
    if let Some(error) = body.get("error") {
        return (
            ResponseTrace {
                id: None,
                model: body.get("model").and_then(Value::as_str).map(str::to_owned),
                role: MessageRole::Unknown,
                parts: Vec::new(),
                stop_reason: None,
                stop_sequence: None,
                usage: usage(body),
                error: Some(error.clone()),
                events: Vec::new(),
                evidence: observed(root),
            },
            true,
        );
    }
    let mut parts = Vec::new();
    match operation {
        OllamaOperation::Chat => {
            if let Some(message) = body.get("message").and_then(Value::as_object) {
                append_chat_parts(message, root, None, &mut parts, issues);
            } else {
                issues.push(ParseIssue::at(
                    OLLAMA_ADAPTER_ID,
                    ParseIssueCode::MissingField,
                    format!("{root}/message"),
                ));
            }
        }
        OllamaOperation::Generate => {
            if let Some(text) = body.get("response").and_then(Value::as_str) {
                parts.push(PromptPart::Text {
                    id: "response_part_0".to_owned(),
                    text: text.to_owned(),
                    evidence: observed(format!("{root}/response")),
                });
            }
            if let Some(thinking) = body.get("thinking").and_then(Value::as_str) {
                parts.push(thinking_part(
                    thinking,
                    format!("response_part_{}", parts.len()),
                    observed(format!("{root}/thinking")),
                ));
            }
        }
    }
    let terminal = body.get("done").and_then(Value::as_bool).unwrap_or(false);
    (
        ResponseTrace {
            id: None,
            model: body.get("model").and_then(Value::as_str).map(str::to_owned),
            role: MessageRole::Assistant,
            parts,
            stop_reason: body
                .get("done_reason")
                .and_then(Value::as_str)
                .map(str::to_owned),
            stop_sequence: None,
            usage: usage(body),
            error: None,
            events: Vec::new(),
            evidence: observed(root),
        },
        terminal,
    )
}

fn append_chat_parts(
    message: &Map<String, Value>,
    root: &str,
    stream_event: Option<u64>,
    parts: &mut Vec<PromptPart>,
    issues: &mut Vec<ParseIssue>,
) {
    let evidence =
        |pointer: String| stream_event.map_or_else(|| observed(pointer), stream_evidence);
    if let Some(content) = message.get("content").and_then(Value::as_str) {
        parts.push(PromptPart::Text {
            id: format!("response_part_{}", parts.len()),
            text: content.to_owned(),
            evidence: evidence(format!("{root}/message/content")),
        });
    }
    if let Some(thinking) = message.get("thinking").and_then(Value::as_str) {
        parts.push(thinking_part(
            thinking,
            format!("response_part_{}", parts.len()),
            evidence(format!("{root}/message/thinking")),
        ));
    }
    if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
        for (index, call) in calls.iter().enumerate() {
            let pointer = format!("{root}/message/tool_calls/{index}");
            parts.push(parse_tool_call_with_evidence(
                call,
                &format!("response_tool_{index}"),
                evidence(pointer.clone()),
                &pointer,
                issues,
            ));
        }
    }
}

struct ParsedStream {
    trace: Option<ResponseTrace>,
    terminal: bool,
}

#[derive(Default)]
struct StreamBuilder {
    model: Option<String>,
    text: String,
    text_event: Option<u64>,
    thinking: String,
    thinking_event: Option<u64>,
    tool_calls: Vec<(u64, Value)>,
    stop_reason: Option<String>,
    usage: BTreeMap<String, Value>,
    error: Option<Value>,
    events: Vec<ResponseEvent>,
    first_event: Option<u64>,
    terminal: bool,
}

fn parse_ndjson_response(
    text: &str,
    operation: OllamaOperation,
    issues: &mut Vec<ParseIssue>,
) -> ParsedStream {
    let mut builder = StreamBuilder::default();
    let mut physical_index = 0_u64;
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let event_index = physical_index;
        physical_index = physical_index.saturating_add(1);
        let body: Value = match serde_json::from_str(line) {
            Ok(body) => body,
            Err(_) => {
                issues.push(ParseIssue::at(
                    OLLAMA_ADAPTER_ID,
                    ParseIssueCode::InvalidStreamEvent,
                    format!("/response/events/{event_index}"),
                ));
                continue;
            }
        };
        let Some(body) = body.as_object() else {
            issues.push(ParseIssue::at(
                OLLAMA_ADAPTER_ID,
                ParseIssueCode::InvalidStreamEvent,
                format!("/response/events/{event_index}"),
            ));
            continue;
        };
        builder.first_event.get_or_insert(event_index);
        let delta_kind = chunk_delta_kind(body, operation);
        builder.events.push(ResponseEvent {
            index: event_index,
            kind: if body.contains_key("error") {
                "error"
            } else {
                match operation {
                    OllamaOperation::Chat => "chat_chunk",
                    OllamaOperation::Generate => "generate_chunk",
                }
            }
            .to_owned(),
            content_index: None,
            delta_kind: Some(delta_kind.to_owned()),
            evidence: stream_evidence(event_index),
        });
        apply_chunk(&mut builder, body, operation, event_index);
    }
    if builder.events.is_empty() {
        return ParsedStream {
            trace: None,
            terminal: false,
        };
    }
    let first_event = builder.first_event.unwrap_or(0);
    let mut parts = Vec::new();
    if !builder.text.is_empty() {
        parts.push(PromptPart::Text {
            id: "response_part_0".to_owned(),
            text: builder.text,
            evidence: stream_evidence(builder.text_event.unwrap_or(first_event)),
        });
    }
    if !builder.thinking.is_empty() {
        parts.push(thinking_part(
            &builder.thinking,
            format!("response_part_{}", parts.len()),
            stream_evidence(builder.thinking_event.unwrap_or(first_event)),
        ));
    }
    for (index, (event_index, call)) in builder.tool_calls.into_iter().enumerate() {
        let issue_path = format!("/response/events/{event_index}/tool_calls/{index}");
        parts.push(parse_tool_call_with_evidence(
            &call,
            &format!("response_tool_{index}"),
            stream_evidence(event_index),
            &issue_path,
            issues,
        ));
    }
    ParsedStream {
        terminal: builder.terminal,
        trace: Some(ResponseTrace {
            id: None,
            model: builder.model,
            role: MessageRole::Assistant,
            parts,
            stop_reason: builder.stop_reason,
            stop_sequence: None,
            usage: builder.usage,
            error: builder.error,
            events: builder.events,
            evidence: stream_evidence(first_event),
        }),
    }
}

fn apply_chunk(
    builder: &mut StreamBuilder,
    body: &Map<String, Value>,
    operation: OllamaOperation,
    event_index: u64,
) {
    builder.model = body
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| builder.model.take());
    builder.usage.extend(usage(body));
    if let Some(error) = body.get("error") {
        builder.error = Some(error.clone());
        builder.terminal = true;
    }
    if body.get("done").and_then(Value::as_bool) == Some(true) {
        builder.terminal = true;
    }
    if let Some(reason) = body.get("done_reason").and_then(Value::as_str) {
        builder.stop_reason = Some(reason.to_owned());
    }
    match operation {
        OllamaOperation::Chat => {
            let Some(message) = body.get("message").and_then(Value::as_object) else {
                return;
            };
            if let Some(content) = message.get("content").and_then(Value::as_str)
                && !content.is_empty()
            {
                builder.text_event.get_or_insert(event_index);
                builder.text.push_str(content);
            }
            if let Some(thinking) = message.get("thinking").and_then(Value::as_str)
                && !thinking.is_empty()
            {
                builder.thinking_event.get_or_insert(event_index);
                builder.thinking.push_str(thinking);
            }
            if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
                builder
                    .tool_calls
                    .extend(calls.iter().cloned().map(|call| (event_index, call)));
            }
        }
        OllamaOperation::Generate => {
            if let Some(response) = body.get("response").and_then(Value::as_str)
                && !response.is_empty()
            {
                builder.text_event.get_or_insert(event_index);
                builder.text.push_str(response);
            }
            if let Some(thinking) = body.get("thinking").and_then(Value::as_str)
                && !thinking.is_empty()
            {
                builder.thinking_event.get_or_insert(event_index);
                builder.thinking.push_str(thinking);
            }
        }
    }
}

fn chunk_delta_kind(body: &Map<String, Value>, operation: OllamaOperation) -> &'static str {
    if body.contains_key("error") {
        return "error";
    }
    if body.get("done").and_then(Value::as_bool) == Some(true) {
        return "done";
    }
    match operation {
        OllamaOperation::Chat => {
            body.get("message")
                .and_then(Value::as_object)
                .map_or("metadata", |message| {
                    if message
                        .get("tool_calls")
                        .and_then(Value::as_array)
                        .is_some_and(|v| !v.is_empty())
                    {
                        "tool_calls"
                    } else if message
                        .get("thinking")
                        .and_then(Value::as_str)
                        .is_some_and(|v| !v.is_empty())
                    {
                        "thinking"
                    } else {
                        "text"
                    }
                })
        }
        OllamaOperation::Generate => {
            if body
                .get("thinking")
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
            {
                "thinking"
            } else {
                "text"
            }
        }
    }
}

fn thinking_part(text: &str, id: String, evidence: Evidence) -> PromptPart {
    PromptPart::Json {
        id,
        value: json!({"type": "thinking", "thinking": text}),
        evidence,
    }
}

fn usage(body: &Map<String, Value>) -> BTreeMap<String, Value> {
    let mut usage = BTreeMap::new();
    for key in [
        "total_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_duration",
        "eval_count",
        "eval_duration",
    ] {
        if let Some(value) = body.get(key) {
            usage.insert(key.to_owned(), value.clone());
        }
    }
    usage
}

fn observed(pointer: impl Into<String>) -> Evidence {
    Evidence::observed(EvidenceSource::JsonPointer {
        pointer: pointer.into(),
    })
}

fn stream_evidence(index: u64) -> Evidence {
    Evidence::observed(EvidenceSource::StreamEvent { index })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_ndjson_keeps_physical_event_indexes() {
        let mut issues = Vec::new();
        let parsed = parse_ndjson_response(
            "not-json\n{\"response\":\"ok\",\"done\":true}\n",
            OllamaOperation::Generate,
            &mut issues,
        );
        let trace = parsed.trace.expect("valid second line must be retained");

        assert_eq!(trace.events[0].index, 1);
        assert_eq!(issues[0].path.as_deref(), Some("/response/events/0"));
    }
}
