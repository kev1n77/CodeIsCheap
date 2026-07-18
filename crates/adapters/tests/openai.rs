use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use codeischeap_adapters::{
    AdapterError, AdapterInput, AdapterOutput, AdapterRegistry, OpenAiAdapter, ParseIssueCode,
    PromptAdapter,
};
use codeischeap_capture_ipc::{
    CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureSource, CapturedBody, CapturedBodyState,
    CapturedRequest,
};
use codeischeap_capture_policy::{CapturePolicy, SanitizedCapture};
use codeischeap_prompt_ir::{MessageRole, PromptIr, PromptPart};
use serde_json::{Value, json};

#[test]
fn responses_fixture_matches_the_golden_prompt_ir() {
    assert_fixture_matches_golden(
        "openai-responses-capture.json",
        "openai-responses-prompt-ir.json",
    );
}

#[test]
fn chat_fixture_matches_the_golden_prompt_ir() {
    assert_fixture_matches_golden("openai-chat-capture.json", "openai-chat-prompt-ir.json");
}

#[test]
fn completions_prompt_arrays_remain_distinct_messages() {
    let capture = sanitized_openai(
        "completion_fixture",
        "/v1/completions",
        json!({
            "model": "gpt-3.5-turbo-instruct",
            "prompt": ["first prompt", "second prompt"],
            "max_tokens": 256
        }),
    );

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result.prompt_ir.expect("completion request must parse");

    assert!(!result.raw_fallback);
    assert_eq!(prompt.operation.as_deref(), Some("completions.create"));
    assert_eq!(prompt.messages.len(), 2);
    assert_eq!(prompt.messages[0].role, MessageRole::User);
    assert!(matches!(
        &prompt.messages[1].parts[0],
        PromptPart::Text { text, .. } if text == "second prompt"
    ));
    assert_eq!(prompt.generation.max_output_tokens, Some(256));
}

#[test]
fn unsupported_content_is_preserved_and_reported_as_partial() {
    let mut envelope = read_capture("openai-responses-capture.json");
    envelope.request.body.content = Some(json!({
        "model": "gpt-5.2",
        "input": [{
            "role": "user",
            "content": [{
                "type": "computer_screenshot",
                "image_url": "https://example.invalid/screenshot.png"
            }]
        }]
    }));
    let capture = CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(envelope)
        .expect("fixture must be in scope");

    let result = AdapterRegistry::default().parse(&capture);
    let prompt = result.prompt_ir.expect("partial request must still parse");

    assert!(!result.raw_fallback);
    assert!(result.issues.iter().any(|issue| {
        issue.code == ParseIssueCode::UnsupportedContent
            && issue.path.as_deref() == Some("/input/0/content/0")
    }));
    assert!(matches!(
        prompt.messages[0].parts[0],
        PromptPart::Unknown { .. }
    ));
}

#[test]
fn adapter_errors_and_panics_are_isolated_before_fallback_candidates_run() {
    let capture = sanitized_fixture("openai-responses-capture.json");
    let mut registry = AdapterRegistry::new();
    registry.register(RejectingAdapter);
    registry.register(PanickingAdapter);
    registry.register(InvalidOutputAdapter);
    registry.register(OpenAiAdapter);

    let result = without_panic_output(|| registry.parse(&capture));

    assert_eq!(result.adapter_id.as_deref(), Some("openai-compatible/v0.1"));
    assert!(result.prompt_ir.is_some());
    assert!(!result.raw_fallback);
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ParseIssueCode::AdapterRejected)
    );
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ParseIssueCode::AdapterPanicked)
    );
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.code == ParseIssueCode::InvalidPromptIr)
    );
}

static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

fn without_panic_output<T>(operation: impl FnOnce() -> T) -> T {
    let _lock = PANIC_HOOK_LOCK
        .lock()
        .expect("panic hook test lock must be available");
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = operation();
    std::panic::set_hook(hook);
    result
}

#[test]
fn unknown_provider_and_invalid_json_degrade_to_raw() {
    let mistral = sanitized(
        "mistral_fixture",
        "api.mistral.ai",
        "/v1/fim/completions",
        CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(json!({"prompt": "complete this"})),
        },
    );
    let unknown = AdapterRegistry::default().parse(&mistral);
    assert!(unknown.raw_fallback);
    assert!(unknown.prompt_ir.is_none());
    assert_eq!(unknown.issues[0].code, ParseIssueCode::NoAdapter);

    let invalid = sanitized(
        "invalid_openai",
        "api.openai.com",
        "/v1/responses",
        CapturedBody {
            state: CapturedBodyState::InvalidJson,
            content: None,
        },
    );
    let rejected = AdapterRegistry::default().parse(&invalid);
    assert!(rejected.raw_fallback);
    assert!(rejected.prompt_ir.is_none());
    assert!(
        rejected
            .issues
            .iter()
            .any(|issue| issue.code == ParseIssueCode::InvalidBody)
    );
    assert!(
        rejected
            .issues
            .iter()
            .any(|issue| issue.code == ParseIssueCode::AllAdaptersFailed)
    );
}

#[derive(Debug, Clone, Copy)]
struct RejectingAdapter;

impl PromptAdapter for RejectingAdapter {
    fn id(&self) -> &'static str {
        "test-rejecting"
    }

    fn detect(&self, _input: AdapterInput<'_>) -> Option<f32> {
        Some(1.0)
    }

    fn parse(&self, _input: AdapterInput<'_>) -> Result<AdapterOutput, AdapterError> {
        Err(AdapterError::at(ParseIssueCode::InvalidField, "/synthetic"))
    }
}

#[derive(Debug, Clone, Copy)]
struct PanickingAdapter;

impl PromptAdapter for PanickingAdapter {
    fn id(&self) -> &'static str {
        "test-panicking"
    }

    fn detect(&self, _input: AdapterInput<'_>) -> Option<f32> {
        Some(1.0)
    }

    fn parse(&self, _input: AdapterInput<'_>) -> Result<AdapterOutput, AdapterError> {
        panic!("synthetic adapter panic")
    }
}

#[derive(Debug, Clone, Copy)]
struct InvalidOutputAdapter;

impl PromptAdapter for InvalidOutputAdapter {
    fn id(&self) -> &'static str {
        "test-invalid-output"
    }

    fn detect(&self, _input: AdapterInput<'_>) -> Option<f32> {
        Some(1.0)
    }

    fn parse(&self, _input: AdapterInput<'_>) -> Result<AdapterOutput, AdapterError> {
        Ok(AdapterOutput {
            prompt_ir: PromptIr::new("", "openai"),
            issues: Vec::new(),
        })
    }
}

fn assert_fixture_matches_golden(capture_name: &str, golden_name: &str) {
    let capture = sanitized_fixture(capture_name);
    let result = AdapterRegistry::default().parse(&capture);
    let mut actual =
        serde_json::to_value(result.prompt_ir.expect("fixture must produce Prompt IR"))
            .expect("Prompt IR must serialize");
    actual
        .as_object_mut()
        .expect("Prompt IR must be an object")
        .remove("metrics");
    let expected: Value = serde_json::from_str(
        &fs::read_to_string(fixtures().join(golden_name)).expect("golden must be readable"),
    )
    .expect("golden must parse");

    assert_eq!(result.adapter_id.as_deref(), Some("openai-compatible/v0.1"));
    assert_eq!(result.confidence, Some(1.0));
    assert!(!result.raw_fallback);
    assert!(result.issues.is_empty());
    assert_eq!(actual, expected);
}

fn sanitized_fixture(name: &str) -> SanitizedCapture {
    CapturePolicy::load_default()
        .expect("policy must load")
        .sanitize_envelope(read_capture(name))
        .expect("fixture must be in scope")
}

fn read_capture(name: &str) -> CaptureEnvelope {
    serde_json::from_str(
        &fs::read_to_string(fixtures().join(name)).expect("fixture must be readable"),
    )
    .expect("fixture must parse")
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn sanitized_openai(capture_id: &str, path: &str, body: Value) -> SanitizedCapture {
    sanitized(
        capture_id,
        "api.openai.com",
        path,
        CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(body),
        },
    )
}

fn sanitized(capture_id: &str, host: &str, path: &str, body: CapturedBody) -> SanitizedCapture {
    let envelope = CaptureEnvelope {
        version: CAPTURE_ENVELOPE_VERSION.to_owned(),
        capture_id: capture_id.to_owned(),
        observed_at_unix_ms: 1_784_071_000_000,
        source: CaptureSource::Mitmproxy,
        attribution: None,
        request: CapturedRequest {
            method: "POST".to_owned(),
            scheme: "https".to_owned(),
            host: host.to_owned(),
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
        .expect("fixture must be in scope")
}
