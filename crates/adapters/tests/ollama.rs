use std::fs;
use std::path::PathBuf;

use codeischeap_adapters::{AdapterRegistry, OLLAMA_ADAPTER_ID, ParseIssueCode};
use codeischeap_capture_ipc::{CaptureEnvelope, CaptureOutcome};
use codeischeap_capture_policy::CapturePolicy;
use codeischeap_prompt_ir::{BodyState, ContextKind, EvidenceSource, MessageRole, PromptPart};
use serde_json::Value;

#[test]
fn chat_fixture_matches_golden_and_maps_local_tools() {
    let result = AdapterRegistry::default().parse(&fixture("ollama-chat-capture.json"));
    let prompt = result.prompt_ir.expect("fixture must produce Prompt IR");
    let actual = serde_json::to_value(&prompt).expect("Prompt IR must serialize");
    let expected: Value = read_json("ollama-chat-prompt-ir.json");

    assert_eq!(result.adapter_id.as_deref(), Some(OLLAMA_ADAPTER_ID));
    assert_eq!(result.confidence, Some(1.0));
    assert!(result.issues.is_empty());
    assert_eq!(actual, expected);
    assert_eq!(prompt.messages[2].role, MessageRole::Tool);
    assert!(matches!(
        prompt.messages[0].parts[1],
        PromptPart::ImageRef { .. }
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
    assert_eq!(response.stop_reason.as_deref(), Some("stop"));
    assert_eq!(response.usage["eval_count"], 24);
    assert!(
        response
            .parts
            .iter()
            .any(|part| matches!(part, PromptPart::ToolUse { .. }))
    );
}

#[test]
fn generate_fixture_reassembles_ndjson_and_suffix_context() {
    let result = AdapterRegistry::default().parse(&fixture("ollama-generate-capture.json"));
    let prompt = result.prompt_ir.expect("fixture must produce Prompt IR");
    let actual = serde_json::to_value(&prompt).expect("Prompt IR must serialize");
    let expected: Value = read_json("ollama-generate-prompt-ir.json");

    assert!(result.issues.is_empty());
    assert_eq!(actual, expected);
    assert_eq!(prompt.completeness.response_body, BodyState::Complete);
    assert_eq!(prompt.context[0].kind, ContextKind::ApplicationState);
    let response = prompt
        .response
        .expect("NDJSON response must be reconstructed");
    assert!(matches!(
        &response.parts[0],
        PromptPart::Text { text, evidence, .. }
            if text == "CodeIsCheap"
                && evidence.source == Some(EvidenceSource::StreamEvent { index: 0 })
    ));
    assert_eq!(response.events.len(), 3);
    assert_eq!(response.usage["prompt_eval_count"], 12);
}

#[test]
fn ndjson_without_done_is_retained_as_partial() {
    let mut envelope: CaptureEnvelope = read_json("ollama-generate-capture.json");
    let Some(CaptureOutcome::Response(response)) = envelope.outcome.as_mut() else {
        panic!("fixture must contain a response");
    };
    response.body.content = Some(Value::String(
        "{\"model\":\"gemma3:4b\",\"response\":\"partial\",\"done\":false}\n".to_owned(),
    ));
    let capture = CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope");
    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result
        .prompt_ir
        .expect("partial response must retain Prompt IR");

    assert_eq!(prompt.completeness.response_body, BodyState::Partial);
    assert!(result.issues.iter().any(|issue| {
        issue.code == ParseIssueCode::MissingField
            && issue.path.as_deref() == Some("/response/events/done")
    }));
}

#[test]
fn invalid_body_degrades_to_raw() {
    let result = AdapterRegistry::default().parse(&fixture("ollama-invalid-capture.json"));
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
