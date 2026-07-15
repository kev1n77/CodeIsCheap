use std::fs;
use std::path::PathBuf;

use codeischeap_adapters::{ANTHROPIC_ADAPTER_ID, AdapterRegistry, ParseIssueCode};
use codeischeap_capture_ipc::{
    CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureSource, CapturedBody, CapturedBodyState,
    CapturedRequest,
};
use codeischeap_capture_policy::{CapturePolicy, SanitizedCapture};
use codeischeap_prompt_ir::{MessageRole, PromptPart};
use serde_json::{Value, json};

#[test]
fn messages_fixture_matches_the_golden_prompt_ir() {
    let capture = sanitized_fixture("anthropic-messages-capture.json");
    let result = AdapterRegistry::default().parse(&capture);
    let actual = serde_json::to_value(result.prompt_ir.expect("fixture must produce Prompt IR"))
        .expect("Prompt IR must serialize");
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
    let envelope: CaptureEnvelope = serde_json::from_str(
        &fs::read_to_string(fixtures().join(name)).expect("fixture must be readable"),
    )
    .expect("fixture must parse");
    CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope")
}

fn sanitized_anthropic(capture_id: &str, path: &str, body: CapturedBody) -> SanitizedCapture {
    let envelope = CaptureEnvelope {
        version: CAPTURE_ENVELOPE_VERSION.to_owned(),
        capture_id: capture_id.to_owned(),
        observed_at_unix_ms: 1_784_072_000_000,
        source: CaptureSource::Gateway,
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
