use codeischeap_capture_ipc::{
    AttributionConfidence, AttributionSource, CAPTURE_ENVELOPE_VERSION, CaptureAttribution,
    CaptureEnvelope, CaptureOutcome, CaptureSource, CapturedBody, CapturedBodyState, CapturedField,
    CapturedRequest, CapturedResponse, RedactionLocation, ResponseCompleteness,
};
use codeischeap_capture_policy::{
    CapturePolicy, MAX_ADDITIONAL_TARGET_HOSTS, PolicyError, normalize_additional_hosts,
};
use schemars::schema_for;

const CHECKED_IN_SCHEMA: &str = include_str!("../../../schemas/capture-policy/v0.1.schema.json");
const CREDENTIAL_CORPUS: &str = include_str!("../../../policies/credential-corpus.v0.1.json");
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
        attribution: None,
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
    assert_eq!(
        policy
            .matching_target(&request("127.0.0.1", "POST", "/api/chat"))
            .map(|target| target.id.as_str()),
        Some("ollama")
    );
    assert_eq!(
        policy
            .matching_target(&request("localhost", "POST", "/api/generate"))
            .map(|target| target.id.as_str()),
        Some("ollama")
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
fn additional_hosts_are_normalized_without_expanding_methods_or_paths() {
    let hosts =
        normalize_additional_hosts(&[" Localhost. ".to_owned(), "gateway.example.test".to_owned()])
            .expect("additional hosts must normalize");
    assert_eq!(hosts, ["gateway.example.test", "localhost"]);

    let policy = CapturePolicy::load_default()
        .expect("default policy must load")
        .with_additional_hosts(&hosts)
        .expect("additional hosts must apply");

    assert_eq!(
        policy
            .matching_target(&request(
                "gateway.example.test",
                "POST",
                "/v1/chat/completions"
            ))
            .map(|target| target.id.as_str()),
        Some("openai")
    );
    for denied in [
        request("gateway.example.test", "GET", "/v1/chat/completions"),
        request("gateway.example.test", "POST", "/admin"),
        request(
            "gateway.example.test.attacker.invalid",
            "POST",
            "/v1/chat/completions",
        ),
    ] {
        assert!(policy.matching_target(&denied).is_none());
    }
}

#[test]
fn additional_hosts_reject_duplicates_invalid_names_and_excessive_scope() {
    assert_eq!(
        normalize_additional_hosts(&["EXAMPLE.test".to_owned(), "example.test.".to_owned()]),
        Err(PolicyError::DuplicateAdditionalHost(
            "example.test".to_owned()
        ))
    );
    for invalid in [
        "bad host",
        "*.example.test",
        "example.test/path",
        "-bad.test",
    ] {
        assert!(matches!(
            normalize_additional_hosts(&[invalid.to_owned()]),
            Err(PolicyError::InvalidAdditionalHost(_))
        ));
    }
    assert_eq!(
        normalize_additional_hosts(
            &(0..=MAX_ADDITIONAL_TARGET_HOSTS)
                .map(|index| format!("host-{index}.example.test"))
                .collect::<Vec<_>>()
        ),
        Err(PolicyError::TooManyAdditionalHosts)
    );
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
fn explicit_client_labels_are_high_confidence_and_not_persisted_as_headers() {
    let policy = CapturePolicy::load_default().expect("default policy must be valid");
    let mut request = request("api.openai.com", "POST", "/v1/responses");
    request.headers = vec![
        CapturedField {
            name: "x-codeischeap-client".to_owned(),
            value: "VS Code".to_owned(),
        },
        CapturedField {
            name: "user-agent".to_owned(),
            value: "curl/8.0".to_owned(),
        },
    ];

    let sanitized = policy
        .sanitize_envelope(envelope(request))
        .expect("client label must sanitize");
    let attribution = sanitized
        .envelope()
        .attribution
        .as_ref()
        .expect("attribution must be present");

    assert_eq!(attribution.application, "VS Code");
    assert_eq!(attribution.source, AttributionSource::ClientLabel);
    assert_eq!(attribution.confidence, AttributionConfidence::High);
    assert!(
        sanitized
            .envelope()
            .request
            .headers
            .iter()
            .all(|field| field.name != "x-codeischeap-client")
    );
}

#[test]
fn user_agents_and_capture_mode_fallbacks_have_explicit_confidence() {
    let policy = CapturePolicy::load_default().expect("default policy must be valid");
    let mut known = request("api.openai.com", "POST", "/v1/responses");
    known.headers.push(CapturedField {
        name: "user-agent".to_owned(),
        value: "curl/8.12.1".to_owned(),
    });
    let known = policy
        .sanitize_envelope(envelope(known))
        .expect("known user agent must sanitize");
    assert_eq!(
        known.envelope().attribution,
        Some(CaptureAttribution {
            application: "curl".to_owned(),
            source: AttributionSource::UserAgent,
            confidence: AttributionConfidence::Medium,
            process_id: None,
        })
    );

    let fallback = policy
        .sanitize_envelope(envelope(request("api.openai.com", "POST", "/v1/responses")))
        .expect("fallback attribution must sanitize");
    assert_eq!(
        fallback.envelope().attribution,
        Some(CaptureAttribution {
            application: "Proxy client".to_owned(),
            source: AttributionSource::CaptureMode,
            confidence: AttributionConfidence::Low,
            process_id: None,
        })
    );
}

#[test]
fn invalid_sidecar_attribution_is_rejected() {
    let policy = CapturePolicy::load_default().expect("default policy must be valid");
    let mut capture = envelope(request("api.openai.com", "POST", "/v1/responses"));
    capture.attribution = Some(CaptureAttribution {
        application: "invalid\nlabel".to_owned(),
        source: AttributionSource::ClientLabel,
        confidence: AttributionConfidence::High,
        process_id: None,
    });

    assert!(matches!(
        policy.sanitize_envelope(capture),
        Err(PolicyError::InvalidAttribution(_))
    ));
}

#[test]
fn versioned_credential_corpus_matches_policy_and_scrubs_every_field_name() {
    let policy = CapturePolicy::load_default().expect("default policy must be valid");
    let corpus: serde_json::Value =
        serde_json::from_str(CREDENTIAL_CORPUS).expect("credential corpus must parse");
    let names = corpus["sensitive_names"]
        .as_array()
        .expect("credential corpus names must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("credential name must be text")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(corpus["version"], "0.1");
    assert_eq!(policy.sensitive_names, names);

    let mut fields = serde_json::Map::new();
    let mut canaries = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let canary = format!("sensitive-canary-{index}");
        fields.insert(
            name.replace('-', "_").to_ascii_uppercase(),
            serde_json::Value::String(canary.clone()),
        );
        canaries.push(canary);
    }
    fields.insert("safe_trace".to_owned(), serde_json::json!("keep"));
    let mut request = request("api.openai.com", "POST", "/v1/responses");
    request.body.content = Some(serde_json::Value::Object(fields));

    let sanitized = policy
        .sanitize_envelope(envelope(request))
        .expect("credential corpus fields must sanitize");
    let encoded = serde_json::to_string(sanitized.envelope()).expect("capture must encode");

    assert_eq!(sanitized.newly_redacted(), names.len());
    for canary in canaries {
        assert!(!encoded.contains(&canary));
    }
    assert!(encoded.contains("safe_trace"));
    assert!(encoded.contains("keep"));
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
