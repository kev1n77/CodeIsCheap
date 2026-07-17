use std::collections::BTreeMap;

use codeischeap_capture_ipc::{
    CaptureOutcome, CapturedBodyState, CapturedResponse, ResponseCompleteness,
};
use codeischeap_prompt_ir::{
    BodyState, Evidence, EvidenceSource, MessageRole, PromptIr, PromptPart, ResponseEvent,
    ResponseTrace,
};
use serde_json::{Map, Value};

use crate::gemini::{GEMINI_ADAPTER_ID, parse_part_with_evidence};
use crate::model::{ParseIssue, ParseIssueCode};

pub(crate) fn parse_gemini_response(
    outcome: Option<&CaptureOutcome>,
    streaming: bool,
    prompt: &mut PromptIr,
    issues: &mut Vec<ParseIssue>,
) {
    let Some(CaptureOutcome::Response(response)) = outcome else {
        return;
    };
    prompt.completeness.response_body = response_body_state(response);
    match response.body.state {
        CapturedBodyState::Json => {
            let Some(value) = response.body.content.as_ref() else {
                return;
            };
            if let Some(chunks) = value.as_array() {
                let parsed = build_chunk_trace(chunks.iter(), false, issues);
                prompt.response = parsed.trace;
                mark_incomplete_stream(parsed.terminal, prompt, issues);
            } else if let Some(body) = value.as_object() {
                prompt.response = Some(parse_json_response(body, issues));
            } else {
                issues.push(ParseIssue::at(
                    GEMINI_ADAPTER_ID,
                    ParseIssueCode::InvalidBody,
                    "/outcome/result/body/content",
                ));
            }
        }
        CapturedBodyState::Text if streaming => {
            let text = response
                .body
                .content
                .as_ref()
                .and_then(Value::as_str)
                .unwrap_or_default();
            let parsed = parse_sse_response(text, issues);
            prompt.response = parsed.trace;
            mark_incomplete_stream(parsed.terminal, prompt, issues);
        }
        CapturedBodyState::Empty => {}
        CapturedBodyState::Text
        | CapturedBodyState::InvalidJson
        | CapturedBodyState::InvalidUtf8
        | CapturedBodyState::Truncated
        | CapturedBodyState::OmittedUnsupportedContentType => {}
    }
}

fn mark_incomplete_stream(terminal: bool, prompt: &mut PromptIr, issues: &mut Vec<ParseIssue>) {
    if prompt.completeness.response_body == BodyState::Complete && !terminal {
        prompt.completeness.response_body = BodyState::Partial;
        issues.push(ParseIssue::at(
            GEMINI_ADAPTER_ID,
            ParseIssueCode::MissingField,
            "/response/events/finishReason",
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

fn parse_json_response(body: &Map<String, Value>, issues: &mut Vec<ParseIssue>) -> ResponseTrace {
    let root = "/outcome/result/body/content";
    if body.contains_key("error") {
        return ResponseTrace {
            id: None,
            model: body
                .get("modelVersion")
                .and_then(Value::as_str)
                .map(str::to_owned),
            role: MessageRole::Unknown,
            parts: Vec::new(),
            stop_reason: None,
            stop_sequence: None,
            usage: value_map(body.get("usageMetadata")),
            error: body.get("error").cloned(),
            events: Vec::new(),
            evidence: observed(root),
        };
    }
    let candidate = body
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.first());
    let parts = candidate
        .and_then(|candidate| candidate.get("content"))
        .and_then(|content| content.get("parts"))
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .enumerate()
                .map(|(index, part)| {
                    let pointer = format!("{root}/candidates/0/content/parts/{index}");
                    parse_part_with_evidence(
                        part,
                        &format!("response_part_{index}"),
                        observed(&pointer),
                        &pointer,
                        issues,
                    )
                })
                .collect()
        })
        .unwrap_or_else(|| {
            issues.push(ParseIssue::at(
                GEMINI_ADAPTER_ID,
                ParseIssueCode::MissingField,
                format!("{root}/candidates/0/content/parts"),
            ));
            Vec::new()
        });
    ResponseTrace {
        id: body
            .get("responseId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        model: body
            .get("modelVersion")
            .and_then(Value::as_str)
            .map(str::to_owned),
        role: candidate
            .and_then(|value| value.get("content"))
            .and_then(|content| content.get("role"))
            .and_then(Value::as_str)
            .map(message_role)
            .unwrap_or(MessageRole::Assistant),
        parts,
        stop_reason: candidate
            .and_then(|value| value.get("finishReason"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        stop_sequence: None,
        usage: value_map(body.get("usageMetadata")),
        error: None,
        events: Vec::new(),
        evidence: observed(root),
    }
}

struct ParsedStream {
    trace: Option<ResponseTrace>,
    terminal: bool,
}

fn parse_sse_response(text: &str, issues: &mut Vec<ParseIssue>) -> ParsedStream {
    let values = parse_sse_values(text, issues);
    build_chunk_trace(values.iter(), true, issues)
}

fn parse_sse_values(text: &str, issues: &mut Vec<ParseIssue>) -> Vec<Value> {
    let mut values = Vec::new();
    let mut data = Vec::new();
    for raw_line in text.split('\n') {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            flush_sse_data(&mut values, &mut data, issues);
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("data:") {
            data.push(value.strip_prefix(' ').unwrap_or(value).to_owned());
        }
    }
    flush_sse_data(&mut values, &mut data, issues);
    values
}

fn flush_sse_data(values: &mut Vec<Value>, data: &mut Vec<String>, issues: &mut Vec<ParseIssue>) {
    if data.is_empty() {
        return;
    }
    let index = values.len();
    let encoded = std::mem::take(data).join("\n");
    if encoded == "[DONE]" {
        return;
    }
    match serde_json::from_str(&encoded) {
        Ok(value) => values.push(value),
        Err(_) => issues.push(ParseIssue::at(
            GEMINI_ADAPTER_ID,
            ParseIssueCode::InvalidStreamEvent,
            format!("/response/events/{index}"),
        )),
    }
}

#[derive(Default)]
struct StreamBuilder {
    id: Option<String>,
    model: Option<String>,
    role: Option<MessageRole>,
    parts: BTreeMap<usize, StreamPart>,
    stop_reason: Option<String>,
    usage: BTreeMap<String, Value>,
    error: Option<Value>,
    events: Vec<ResponseEvent>,
    first_evidence: Option<Evidence>,
}

enum StreamPart {
    Text { evidence: Evidence, text: String },
    Value { evidence: Evidence, value: Value },
}

fn build_chunk_trace<'a>(
    chunks: impl Iterator<Item = &'a Value>,
    stream_evidence_enabled: bool,
    issues: &mut Vec<ParseIssue>,
) -> ParsedStream {
    let mut builder = StreamBuilder::default();
    for (index, chunk) in chunks.enumerate() {
        let event_index = u64::try_from(index).unwrap_or(u64::MAX);
        let Some(body) = chunk.as_object() else {
            issues.push(ParseIssue::at(
                GEMINI_ADAPTER_ID,
                ParseIssueCode::InvalidStreamEvent,
                format!("/response/events/{index}"),
            ));
            continue;
        };
        let event_evidence = if stream_evidence_enabled {
            stream_evidence(event_index)
        } else {
            observed(format!("/outcome/result/body/content/{index}"))
        };
        builder
            .first_evidence
            .get_or_insert_with(|| event_evidence.clone());
        builder.events.push(ResponseEvent {
            index: event_index,
            kind: if body.contains_key("error") {
                "error"
            } else {
                "generate_content_chunk"
            }
            .to_owned(),
            content_index: None,
            delta_kind: None,
            evidence: event_evidence,
        });
        apply_chunk(&mut builder, body, event_index, stream_evidence_enabled);
    }
    if builder.events.is_empty() {
        return ParsedStream {
            trace: None,
            terminal: false,
        };
    }
    let trace_evidence = builder
        .first_evidence
        .clone()
        .unwrap_or_else(|| stream_evidence(0));
    let parts = std::mem::take(&mut builder.parts)
        .into_iter()
        .map(|(index, part)| match part {
            StreamPart::Text { evidence, text } => PromptPart::Text {
                id: format!("response_part_{index}"),
                text,
                evidence,
            },
            StreamPart::Value { evidence, value } => parse_part_with_evidence(
                &value,
                &format!("response_part_{index}"),
                evidence,
                &format!("/response/events/{index}/parts/{index}"),
                issues,
            ),
        })
        .collect();
    let terminal = builder.stop_reason.is_some() || builder.error.is_some();
    ParsedStream {
        terminal,
        trace: Some(ResponseTrace {
            id: builder.id,
            model: builder.model,
            role: builder.role.unwrap_or(MessageRole::Assistant),
            parts,
            stop_reason: builder.stop_reason,
            stop_sequence: None,
            usage: builder.usage,
            error: builder.error,
            events: builder.events,
            evidence: trace_evidence,
        }),
    }
}

fn apply_chunk(
    builder: &mut StreamBuilder,
    body: &Map<String, Value>,
    event_index: u64,
    stream_evidence_enabled: bool,
) {
    builder.id = body
        .get("responseId")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| builder.id.take());
    builder.model = body
        .get("modelVersion")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| builder.model.take());
    builder.usage.extend(value_map(body.get("usageMetadata")));
    if let Some(error) = body.get("error") {
        builder.error = Some(error.clone());
    }
    let Some(candidate) = body
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.first())
    else {
        return;
    };
    if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
        builder.stop_reason = Some(reason.to_owned());
    }
    let Some(content) = candidate.get("content") else {
        return;
    };
    if let Some(role) = content.get("role").and_then(Value::as_str) {
        builder.role = Some(message_role(role));
    }
    let Some(parts) = content.get("parts").and_then(Value::as_array) else {
        return;
    };
    for (index, part) in parts.iter().enumerate() {
        let evidence = if stream_evidence_enabled {
            stream_evidence(event_index)
        } else {
            observed(format!(
                "/outcome/result/body/content/{event_index}/candidates/0/content/parts/{index}"
            ))
        };
        if let Some(text) = part.get("text").and_then(Value::as_str) {
            match builder
                .parts
                .entry(index)
                .or_insert_with(|| StreamPart::Text {
                    evidence,
                    text: String::new(),
                }) {
                StreamPart::Text { text: output, .. } => output.push_str(text),
                StreamPart::Value { .. } => {}
            }
        } else {
            builder.parts.insert(
                index,
                StreamPart::Value {
                    evidence,
                    value: part.clone(),
                },
            );
        }
    }
}

fn message_role(role: &str) -> MessageRole {
    match role {
        "model" => MessageRole::Assistant,
        "user" => MessageRole::User,
        "function" => MessageRole::Tool,
        "system" => MessageRole::System,
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
    use serde_json::json;

    use super::*;

    #[test]
    fn multiline_sse_data_is_parsed() {
        let mut issues = Vec::new();
        let values = parse_sse_values(
            ": keepalive\r\ndata: {\"candidates\":\r\ndata: []}\r\n\r\n",
            &mut issues,
        );
        assert_eq!(values, vec![json!({"candidates": []})]);
        assert!(issues.is_empty());
    }
}
