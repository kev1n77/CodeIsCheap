use codeischeap_capture_ipc::{
    CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureOutcome, CaptureSource, CapturedBody,
    CapturedBodyState, CapturedField, CapturedRequest, CapturedResponse, RedactionLocation,
    ResponseCompleteness,
};
use codeischeap_capture_policy::{CapturePolicy, PolicyError};
use schemars::schema_for;

const CHECKED_IN_SCHEMA: &str = include_str!("../../../schemas/capture-policy/v0.1.schema.json");
const SIDECAR_FIXTURE: &str =
    include_str!("../../capture-ipc/tests/fixtures/mitmproxy-request.json");

fn request(host: &str, method: &str, path: &str) -> CapturedRequest {
    CapturedRequest {
        method: method.to_owned(),
        scheme: "https".to_owned(),
        host: host.to_owned(),
        port: 443,
        path: path.to_owned(),
        query: Vec::new(),
        headers: Vec::new(),
        body: CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(serde_json::json!({"messages": []})),
        },
    }
}

fn envelope(request: CapturedRequest) -> CaptureEnvelope {
    CaptureEnvelope {
        version: CAPTURE_ENVELOPE_VERSION.to_owned(),
        capture_id: "capture_policy_test".to_owned(),
        observed_at_unix_ms: 1_721_000_000_000,
        source: CaptureSource::Mitmproxy,
        request,
        outcome: None,
        redactions: Vec::new(),
    }
}

#[test]
fn default_policy_is_valid_and_matches_supported_endpoints() {
    let policy = CapturePolicy::load_default().expect("default policy must be valid");

    assert_eq!(
        policy
            .matching_target(&request("api.openai.com", "POST", "/v1/chat/completions"))
            .map(|target| target.id.as_str()),
        Some("openai")
    );
    assert_eq!(
        policy
            .matching_target(&request(
                "generativelanguage.googleapis.com",
                "POST",
                "/v1beta/models/gemini-pro:streamGenerateContent"
            ))
            .map(|target| target.id.as_str()),
        Some("gemini")
    );
}

#[test]
fn policy_rejects_host_suffix_unlisted_path_and_method() {
    let policy = CapturePolicy::load_default().expect("default policy must be valid");

    for denied in [
        request("api.openai.com.example.com", "POST", "/v1/chat/completions"),
        request("api.openai.com", "POST", "/v1/files"),
        request("api.openai.com", "GET", "/v1/chat/completions"),
    ] {
        assert!(policy.matching_target(&denied).is_none());
        assert_eq!(
            policy.sanitize_envelope(envelope(denied)),
            Err(PolicyError::OutOfScope)
        );
    }
}

#[test]
fn core_scrubber_removes_canaries_before_persistence() {
    let policy = CapturePolicy::load_default().expect("default policy must be valid");
    let mut request = request("api.openai.com", "POST", "/v1/responses");
    request.headers = vec![
        CapturedField {
            name: "Authorization".to_owned(),
            value: "Bearer header-canary".to_owned(),
        },
        CapturedField {
            name: "x-request-id".to_owned(),
            value: "request_1".to_owned(),
        },
    ];
    request.query = vec![CapturedField {
        name: "access_token".to_owned(),
        value: "query-canary".to_owned(),
    }];
    request.body.content = Some(serde_json::json!({
        "input": "preserved prompt",
        "metadata": {
            "client_secret": "body-canary",
            "nested": [{"session_token": "nested-canary", "trace": "keep"}]
        }
    }));

    let sanitized = policy
        .sanitize_envelope(envelope(request))
        .expect("supported request must be sanitized");
    let encoded = serde_json::to_string(sanitized.envelope()).expect("envelope must encode");

    assert_eq!(sanitized.target_id(), "openai");
    assert_eq!(sanitized.newly_redacted(), 4);
    for canary in [
        "header-canary",
        "query-canary",
        "body-canary",
        "nested-canary",
    ] {
        assert!(!encoded.contains(canary));
    }
    assert!(encoded.contains("preserved prompt"));
    assert!(encoded.contains("request_1"));
    assert!(encoded.contains("trace"));
}

#[test]
fn response_headers_and_json_credentials_are_removed_before_persistence() {
    let policy = CapturePolicy::load_default().expect("default policy must be valid");
    let mut capture = envelope(request("api.openai.com", "POST", "/v1/responses"));
    capture.outcome = Some(CaptureOutcome::Response(CapturedResponse {
        status: 200,
        headers: vec![
            CapturedField {
                name: "set-cookie".to_owned(),
                value: "session=response-header-canary".to_owned(),
            },
            CapturedField {
                name: "x-request-id".to_owned(),
                value: "response_1".to_owned(),
            },
        ],
        body: CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(serde_json::json!({
                "output": "preserved response",
                "metadata": {"access_token": "response-body-canary"}
            })),
        },
        duration_ms: 42,
        completeness: ResponseCompleteness::Complete,
    }));

    let sanitized = policy
        .sanitize_envelope(capture)
        .expect("supported response must be sanitized");
    let encoded = serde_json::to_string(sanitized.envelope()).expect("envelope must encode");

    assert_eq!(sanitized.newly_redacted(), 2);
    assert!(!encoded.contains("response-header-canary"));
    assert!(!encoded.contains("response-body-canary"));
    assert!(encoded.contains("preserved response"));
    assert!(encoded.contains("response_1"));
    assert!(sanitized.envelope().redactions.iter().any(|redaction| {
        redaction.location == RedactionLocation::ResponseHeader && redaction.name == "set-cookie"
    }));
    assert!(sanitized.envelope().redactions.iter().any(|redaction| {
        redaction.location == RedactionLocation::ResponseBody && redaction.name == "access_token"
    }));
}

#[test]
fn sidecar_fixture_is_in_scope_and_needs_no_second_redaction() {
    let policy = CapturePolicy::load_default().expect("default policy must be valid");
    let fixture: CaptureEnvelope =
        serde_json::from_str(SIDECAR_FIXTURE).expect("fixture must deserialize");

    let sanitized = policy
        .sanitize_envelope(fixture)
        .expect("fixture must be in scope");

    assert_eq!(sanitized.target_id(), "openai");
    assert_eq!(sanitized.newly_redacted(), 0);
}

#[test]
fn checked_in_schema_matches_the_rust_contract() {
    let generated =
        serde_json::to_value(schema_for!(CapturePolicy)).expect("schema must serialize");
    let checked_in: serde_json::Value =
        serde_json::from_str(CHECKED_IN_SCHEMA).expect("checked-in schema must be valid JSON");

    assert_eq!(
        checked_in, generated,
        "schema drifted; run `cargo run -p codeischeap-capture-policy --bin export-policy-schema -- schemas/capture-policy/v0.1.schema.json`"
    );
}
