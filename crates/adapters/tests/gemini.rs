use std::fs;
use std::path::PathBuf;

use codeischeap_adapters::{AdapterRegistry, GEMINI_ADAPTER_ID, ParseIssueCode};
use codeischeap_capture_ipc::{CaptureEnvelope, CaptureOutcome};
use codeischeap_capture_policy::CapturePolicy;
use codeischeap_prompt_ir::{BodyState, EvidenceSource, MessageRole, PromptPart};
use serde_json::Value;

#[test]
fn generate_content_fixture_matches_golden_and_maps_gemini_semantics() {
    let result = AdapterRegistry::default().parse(&fixture("gemini-generate-content-capture.json"));
    let prompt = result.prompt_ir.expect("fixture must produce Prompt IR");
    let actual = serde_json::to_value(&prompt).expect("Prompt IR must serialize");
    let expected: Value = read_json("gemini-generate-content-prompt-ir.json");

    assert_eq!(result.adapter_id.as_deref(), Some(GEMINI_ADAPTER_ID));
    assert_eq!(result.confidence, Some(1.0));
    assert!(result.issues.is_empty());
    assert_eq!(actual, expected);
    assert_eq!(prompt.model.as_deref(), Some("gemini-2.5-pro"));
    assert_eq!(prompt.messages[2].role, MessageRole::Tool);
    assert!(matches!(
        prompt.messages[0].parts[1],
        PromptPart::ImageRef { .. }
    ));
    assert!(matches!(
        prompt.messages[0].parts[2],
        PromptPart::AudioRef { .. }
    ));
    assert!(matches!(
        prompt.messages[1].parts[0],
        PromptPart::ToolUse { .. }
    ));
    assert!(matches!(
        prompt.messages[2].parts[0],
        PromptPart::ToolResult { .. }
    ));
    let response = prompt
        .response
        .expect("JSON response must be reconstructed");
    assert_eq!(response.stop_reason.as_deref(), Some("STOP"));
    assert_eq!(response.usage["totalTokenCount"], 172);
    assert!(matches!(response.parts[1], PromptPart::ToolUse { .. }));
}

#[test]
fn streaming_fixture_reassembles_text_and_usage() {
    let result = AdapterRegistry::default().parse(&fixture("gemini-stream-content-capture.json"));
    let prompt = result.prompt_ir.expect("fixture must produce Prompt IR");
    let actual = serde_json::to_value(&prompt).expect("Prompt IR must serialize");
    let expected: Value = read_json("gemini-stream-content-prompt-ir.json");

    assert!(result.issues.is_empty());
    assert_eq!(actual, expected);
    assert_eq!(prompt.completeness.response_body, BodyState::Complete);
    let response = prompt.response.expect("SSE response must be reconstructed");
    assert!(matches!(
        &response.parts[0],
        PromptPart::Text { text, evidence, .. }
            if text == "CodeIsCheap"
                && evidence.source == Some(EvidenceSource::StreamEvent { index: 0 })
    ));
    assert_eq!(response.usage["totalTokenCount"], 9);
    assert_eq!(response.events.len(), 2);
}

#[test]
fn stream_without_finish_reason_is_retained_as_partial() {
    let mut envelope: CaptureEnvelope = read_json("gemini-stream-content-capture.json");
    let Some(CaptureOutcome::Response(response)) = envelope.outcome.as_mut() else {
        panic!("fixture must have a response");
    };
    response.body.content = Some(Value::String(
        "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"partial\"}]}}]}\n\n"
            .to_owned(),
    ));
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
            && issue.path.as_deref() == Some("/response/events/finishReason")
    }));
}

#[test]
fn invalid_body_degrades_to_raw() {
    let result = AdapterRegistry::default().parse(&fixture("gemini-invalid-capture.json"));
    assert!(result.raw_fallback);
    assert!(result.prompt_ir.is_none());
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ParseIssueCode::InvalidBody)
    );
}

fn fixture(name: &str) -> codeischeap_capture_policy::SanitizedCapture {
    CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(read_json(name))
        .expect("fixture must be in scope")
}

fn read_json<T: serde::de::DeserializeOwned>(name: &str) -> T {
    serde_json::from_str(
        &fs::read_to_string(fixtures().join(name)).expect("fixture must be readable"),
    )
    .expect("fixture must be valid JSON")
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}
