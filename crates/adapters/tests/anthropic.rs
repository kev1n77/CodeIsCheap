use std::fs;
use std::path::PathBuf;

use codeischeap_adapters::{ANTHROPIC_ADAPTER_ID, AdapterRegistry, ParseIssueCode};
use codeischeap_capture_ipc::{
    CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureOutcome, CaptureSource, CapturedBody,
    CapturedBodyState, CapturedRequest, CapturedResponse, ResponseCompleteness,
};
use codeischeap_capture_policy::{CapturePolicy, SanitizedCapture};
use codeischeap_prompt_ir::{BodyState, EvidenceSource, MessageRole, PromptPart};
use serde_json::{Value, json};

#[test]
fn messages_fixture_matches_the_golden_prompt_ir() {
    let capture = sanitized_fixture("anthropic-messages-capture.json");
    let result = AdapterRegistry::default().parse(&capture);
    let mut actual =
        serde_json::to_value(result.prompt_ir.expect("fixture must produce Prompt IR"))
            .expect("Prompt IR must serialize");
    actual
        .as_object_mut()
        .expect("Prompt IR must be an object")
        .remove("metrics");
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(fixtures().join("anthropic-messages-prompt-ir.json"))
            .expect("golden must be readable"),
    )
    .expect("golden must parse");

    assert_eq!(result.adapter_id.as_deref(), Some(ANTHROPIC_ADAPTER_ID));
    assert_eq!(result.confidence, Some(1.0));
    assert!(!result.raw_fallback);
    assert!(result.issues.is_empty());
    assert_eq!(actual, expected);
}

#[test]
fn messages_sse_fixture_matches_the_golden_response_trace() {
    let capture = sanitized_fixture("anthropic-messages-sse-capture.json");
    let result = AdapterRegistry::default().parse(&capture);
    let mut actual =
        serde_json::to_value(result.prompt_ir.expect("fixture must produce Prompt IR"))
            .expect("Prompt IR must serialize");
    actual
        .as_object_mut()
        .expect("Prompt IR must be an object")
        .remove("metrics");
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(fixtures().join("anthropic-messages-sse-prompt-ir.json"))
            .expect("golden must be readable"),
    )
    .expect("golden must parse");

    assert_eq!(result.adapter_id.as_deref(), Some(ANTHROPIC_ADAPTER_ID));
    assert!(!result.raw_fallback);
    assert!(result.issues.is_empty());
    assert_eq!(actual, expected);
}

#[test]
fn messages_sse_reassembles_text_tools_usage_and_unknown_events() {
    let result =
        AdapterRegistry::default().parse(&sanitized_fixture("anthropic-messages-sse-capture.json"));
    let prompt = result.prompt_ir.expect("fixture must parse");
    let response = prompt.response.expect("response trace must exist");

    assert_eq!(prompt.completeness.response_body, BodyState::Complete);
    assert_eq!(response.id.as_deref(), Some("msg_fixture_1"));
    assert_eq!(response.stop_reason.as_deref(), Some("tool_use"));
    assert_eq!(response.usage["input_tokens"], 42);
    assert_eq!(response.usage["output_tokens"], 18);
    assert!(matches!(
        &response.parts[0],
        PromptPart::Text { text, evidence, .. }
            if text == "I will inspect the workspace."
                && evidence.source == Some(EvidenceSource::StreamEvent { index: 2 })
    ));
    assert!(matches!(
        &response.parts[1],
        PromptPart::ToolUse { id, name, input, evidence }
            if id == "toolu_fixture_1"
                && name == "read_file"
                && input == &json!({"path": "Cargo.toml"})
                && evidence.source == Some(EvidenceSource::StreamEvent { index: 6 })
    ));
    assert!(
        response
            .events
            .iter()
            .any(|event| event.kind == "future_event")
    );
}

#[test]
fn complete_transport_without_message_stop_is_marked_partial() {
    let mut envelope = read_fixture("anthropic-messages-sse-capture.json");
    let Some(CaptureOutcome::Response(response)) = envelope.outcome.as_mut() else {
        panic!("fixture must contain a response");
    };
    let text = response
        .body
        .content
        .as_mut()
        .and_then(|value| value.as_str())
        .expect("fixture body must be text")
        .replace(
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
            "",
        );
    response.body.content = Some(Value::String(text));
    let capture = CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope");

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result
        .prompt_ir
        .expect("partial stream must retain Prompt IR");

    assert_eq!(prompt.completeness.response_body, BodyState::Partial);
    assert!(result.issues.iter().any(|issue| {
        issue.code == ParseIssueCode::MissingField
            && issue.path.as_deref() == Some("/response/events/message_stop")
    }));
}

#[test]
fn cancelled_sse_retains_the_request_and_marks_response_partial() {
    let mut envelope = read_fixture("anthropic-messages-sse-capture.json");
    let Some(CaptureOutcome::Response(response)) = envelope.outcome.as_mut() else {
        panic!("fixture must contain a response");
    };
    response.completeness = ResponseCompleteness::Incomplete;
    response.body = CapturedBody {
        state: CapturedBodyState::Truncated,
        content: None,
    };
    let capture = CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope");

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result
        .prompt_ir
        .expect("cancelled response must retain request Prompt IR");

    assert_eq!(prompt.completeness.response_body, BodyState::Partial);
    assert!(prompt.response.is_none());
    assert!(!result.raw_fallback);
}

#[test]
fn non_sse_text_never_creates_synthetic_stream_evidence() {
    let mut envelope = read_fixture("anthropic-messages-sse-capture.json");
    let Some(CaptureOutcome::Response(response)) = envelope.outcome.as_mut() else {
        panic!("fixture must contain a response");
    };
    response.body.content = Some(Value::String("service unavailable".to_owned()));
    let capture = CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope");

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result
        .prompt_ir
        .expect("request Prompt IR must remain available");

    assert_eq!(prompt.completeness.response_body, BodyState::Unsupported);
    assert!(prompt.response.is_none());
    assert!(result.issues.iter().any(|issue| {
        issue.code == ParseIssueCode::InvalidBody
            && issue.path.as_deref() == Some("/response/events")
    }));
}

#[test]
fn sse_error_event_is_a_complete_failed_trace() {
    let mut envelope = read_fixture("anthropic-messages-sse-capture.json");
    let Some(CaptureOutcome::Response(response)) = envelope.outcome.as_mut() else {
        panic!("fixture must contain a response");
    };
    response.body.content = Some(Value::String(
        "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n"
            .to_owned(),
    ));
    let capture = CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope");

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result
        .prompt_ir
        .expect("error stream must retain Prompt IR");
    let response = prompt.response.expect("response trace must exist");

    assert_eq!(prompt.completeness.response_body, BodyState::Complete);
    assert_eq!(
        response.error.as_ref().and_then(|error| error.get("type")),
        Some(&json!("overloaded_error"))
    );
    assert!(result.issues.is_empty());
}

#[test]
fn malformed_tool_json_is_preserved_as_partial_evidence() {
    let mut envelope = read_fixture("anthropic-messages-sse-capture.json");
    let Some(CaptureOutcome::Response(response)) = envelope.outcome.as_mut() else {
        panic!("fixture must contain a response");
    };
    let text = response
        .body
        .content
        .as_ref()
        .and_then(Value::as_str)
        .expect("fixture body must be text")
        .replace("\\\"Cargo.toml\\\"}", "\\\"Cargo.toml\\\"");
    response.body.content = Some(Value::String(text));
    let capture = CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope");

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result
        .prompt_ir
        .expect("malformed tool input must retain Prompt IR");
    let response = prompt.response.expect("response trace must exist");

    assert!(result.issues.iter().any(|issue| {
        issue.code == ParseIssueCode::InvalidField
            && issue.path.as_deref() == Some("/response/content/1/input")
    }));
    assert!(matches!(
        &response.parts[1],
        PromptPart::ToolUse { input, .. } if input.get("partial_json").is_some()
    ));
}

#[test]
fn non_streaming_messages_response_is_structured() {
    let mut envelope = sanitized_anthropic(
        "anthropic_json_response",
        "/v1/messages",
        CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(json!({
                "model": "claude-sonnet-4-5",
                "max_tokens": 128,
                "messages": [{"role": "user", "content": "Name the workspace."}]
            })),
        },
    )
    .into_envelope();
    envelope.outcome = Some(CaptureOutcome::Response(CapturedResponse {
        status: 200,
        headers: vec![],
        body: CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(json!({
                "id": "msg_json_1",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-4-5",
                "content": [{"type": "text", "text": "CodeIsCheap"}],
                "stop_reason": "end_turn",
                "stop_sequence": null,
                "usage": {"input_tokens": 12, "output_tokens": 4}
            })),
        },
        duration_ms: 51,
        completeness: ResponseCompleteness::Complete,
    }));
    let capture = CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("capture must be in scope");

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result.prompt_ir.expect("JSON response must parse");
    let response = prompt.response.expect("response trace must exist");

    assert_eq!(prompt.completeness.response_body, BodyState::Complete);
    assert_eq!(response.stop_reason.as_deref(), Some("end_turn"));
    assert!(matches!(
        &response.parts[0],
        PromptPart::Text { text, .. } if text == "CodeIsCheap"
    ));
    assert!(result.issues.is_empty());
}

#[test]
fn messages_preserve_media_tools_and_tool_results() {
    let result =
        AdapterRegistry::default().parse(&sanitized_fixture("anthropic-messages-capture.json"));
    let prompt = result.prompt_ir.expect("fixture must parse");

    assert_eq!(prompt.operation.as_deref(), Some("messages.create"));
    assert_eq!(prompt.model.as_deref(), Some("claude-sonnet-4-5"));
    assert_eq!(prompt.messages[2].role, MessageRole::Tool);
    assert!(matches!(
        &prompt.messages[0].parts[1],
        PromptPart::ImageRef { location, media_type, .. }
            if location == "inline:base64" && media_type.as_deref() == Some("image/png")
    ));
    assert!(matches!(
        &prompt.messages[1].parts[0],
        PromptPart::ToolUse { id, name, .. }
            if id == "toolu_read_1" && name == "read_file"
    ));
    assert!(matches!(
        &prompt.messages[2].parts[0],
        PromptPart::ToolResult { tool_use_id, .. } if tool_use_id == "toolu_read_1"
    ));
    assert_eq!(prompt.generation.max_output_tokens, Some(2048));
    assert_eq!(prompt.generation.stop, ["</done>"]);
    assert_eq!(prompt.vendor["anthropic_version"], "2023-06-01");
}

#[test]
fn legacy_complete_requests_remain_supported() {
    let capture = sanitized_anthropic(
        "anthropic_complete",
        "/v1/complete",
        CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(json!({
                "model": "claude-2.1",
                "prompt": "\n\nHuman: Explain Cargo features.\n\nAssistant:",
                "max_tokens": 256,
                "stop_sequences": ["\n\nHuman:"]
            })),
        },
    );

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result.prompt_ir.expect("legacy completion must parse");

    assert_eq!(prompt.operation.as_deref(), Some("completions.create"));
    assert_eq!(prompt.messages.len(), 1);
    assert!(matches!(
        &prompt.messages[0].parts[0],
        PromptPart::Text { text, .. } if text.contains("Explain Cargo features")
    ));
    assert!(result.issues.is_empty());
}

#[test]
fn unsupported_blocks_are_preserved_as_partial_issues() {
    let capture = sanitized_anthropic(
        "anthropic_thinking",
        "/v1/messages",
        CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(json!({
                "model": "claude-sonnet-4-5",
                "max_tokens": 128,
                "messages": [{
                    "role": "assistant",
                    "content": [{"type": "thinking", "thinking": "hidden reasoning"}]
                }]
            })),
        },
    );

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result.prompt_ir.expect("partial request must parse");

    assert!(!result.raw_fallback);
    assert!(result.issues.iter().any(|issue| {
        issue.code == ParseIssueCode::UnsupportedContent
            && issue.path.as_deref() == Some("/messages/0/content/0")
    }));
    assert!(matches!(
        prompt.messages[0].parts[0],
        PromptPart::Unknown { .. }
    ));
}

#[test]
fn truncated_anthropic_requests_degrade_to_raw() {
    let capture = sanitized_anthropic(
        "anthropic_truncated",
        "/v1/messages",
        CapturedBody {
            state: CapturedBodyState::Truncated,
            content: None,
        },
    );

    let result = AdapterRegistry::default().parse(&capture);

    assert!(result.raw_fallback);
    assert!(result.prompt_ir.is_none());
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ParseIssueCode::InvalidBody)
    );
}

fn sanitized_fixture(name: &str) -> SanitizedCapture {
    let envelope = read_fixture(name);
    CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope")
}

fn read_fixture(name: &str) -> CaptureEnvelope {
    serde_json::from_str(
        &fs::read_to_string(fixtures().join(name)).expect("fixture must be readable"),
    )
    .expect("fixture must parse")
}

fn sanitized_anthropic(capture_id: &str, path: &str, body: CapturedBody) -> SanitizedCapture {
    let envelope = CaptureEnvelope {
        version: CAPTURE_ENVELOPE_VERSION.to_owned(),
        capture_id: capture_id.to_owned(),
        observed_at_unix_ms: 1_784_072_000_000,
        source: CaptureSource::Gateway,
        attribution: None,
        request: CapturedRequest {
            method: "POST".to_owned(),
            scheme: "https".to_owned(),
            host: "api.anthropic.com".to_owned(),
            port: 443,
            path: path.to_owned(),
            query: Vec::new(),
            headers: Vec::new(),
            body,
        },
        outcome: None,
        redactions: Vec::new(),
    };
    CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("capture must be in scope")
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}
