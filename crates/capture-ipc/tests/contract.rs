use codeischeap_capture_ipc::{
    CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureOutcome, CaptureSource, CapturedBody,
    CapturedBodyState, CapturedField, CapturedRequest, CapturedResponse, IpcError,
    ResponseCompleteness, receive_from_reader,
};
use schemars::schema_for;
use tokio::io::{AsyncWriteExt, BufReader};

const CHECKED_IN_SCHEMA: &str = include_str!("../../../schemas/capture-envelope/v0.1.schema.json");
const MITMPROXY_FIXTURE: &str = include_str!("fixtures/mitmproxy-request.json");

fn sample_envelope() -> CaptureEnvelope {
    CaptureEnvelope {
        version: CAPTURE_ENVELOPE_VERSION.to_owned(),
        capture_id: "flow_test_1".to_owned(),
        observed_at_unix_ms: 1_721_000_000_000,
        source: CaptureSource::Mitmproxy,
        request: CapturedRequest {
            method: "POST".to_owned(),
            scheme: "https".to_owned(),
            host: "api.openai.com".to_owned(),
            port: 443,
            path: "/v1/chat/completions".to_owned(),
            query: Vec::new(),
            headers: Vec::new(),
            body: CapturedBody {
                state: CapturedBodyState::Json,
                content: Some(
                    serde_json::json!({"messages": [{"role": "user", "content": "hello"}]}),
                ),
            },
        },
        outcome: None,
        redactions: Vec::new(),
    }
}

async fn framed_reader(
    token: &str,
    envelope: &CaptureEnvelope,
) -> BufReader<tokio::io::DuplexStream> {
    let (mut writer, reader) = tokio::io::duplex(16 * 1024);
    let auth = serde_json::json!({
        "protocol": "codeischeap.capture-ipc",
        "version": "0.1",
        "token": token,
    });
    let mut frames = serde_json::to_vec(&auth).expect("auth frame must serialize");
    frames.push(b'\n');
    frames.extend(serde_json::to_vec(envelope).expect("envelope must serialize"));
    frames.push(b'\n');
    tokio::spawn(async move {
        writer
            .write_all(&frames)
            .await
            .expect("frames must be writable");
    });
    BufReader::new(reader)
}

#[tokio::test]
async fn accepts_an_authenticated_envelope() {
    let expected = sample_envelope();
    let mut reader = framed_reader("synthetic-token", &expected).await;

    let received = receive_from_reader(&mut reader, "synthetic-token")
        .await
        .expect("valid frames must be accepted");

    assert_eq!(received, expected);
}

#[tokio::test]
async fn response_outcomes_round_trip_through_authenticated_ipc() {
    let mut expected = sample_envelope();
    expected.outcome = Some(CaptureOutcome::Response(CapturedResponse {
        status: 200,
        headers: vec![CapturedField {
            name: "content-type".to_owned(),
            value: "text/event-stream".to_owned(),
        }],
        body: CapturedBody {
            state: CapturedBodyState::Text,
            content: Some(serde_json::Value::String(
                "data: {\"type\":\"done\"}\n\n".to_owned(),
            )),
        },
        duration_ms: 73,
        completeness: ResponseCompleteness::Complete,
    }));
    let mut reader = framed_reader("synthetic-token", &expected).await;

    let received = receive_from_reader(&mut reader, "synthetic-token")
        .await
        .expect("response outcome must be accepted");

    assert_eq!(received, expected);
}

#[tokio::test]
async fn rejects_an_invalid_token_without_echoing_it() {
    let mut reader = framed_reader("wrong-token", &sample_envelope()).await;

    let error = receive_from_reader(&mut reader, "expected-token")
        .await
        .expect_err("invalid tokens must be rejected");

    assert!(matches!(error, IpcError::Unauthorized));
    assert!(!error.to_string().contains("wrong-token"));
}

#[test]
fn mitmproxy_fixture_matches_the_rust_contract() {
    let envelope: CaptureEnvelope =
        serde_json::from_str(MITMPROXY_FIXTURE).expect("mitmproxy fixture must deserialize");

    assert_eq!(envelope.source, CaptureSource::Mitmproxy);
    assert_eq!(envelope.request.host, "api.openai.com");
    assert_eq!(
        envelope.request.body.content,
        Some(serde_json::json!({
            "messages": [{"role": "user", "content": "keep this prompt"}],
            "metadata": {"trace": "keep"}
        }))
    );
    assert_eq!(envelope.redactions.len(), 5);
}

#[test]
fn checked_in_schema_matches_the_rust_contract() {
    let generated =
        serde_json::to_value(schema_for!(CaptureEnvelope)).expect("schema must serialize");
    let checked_in: serde_json::Value =
        serde_json::from_str(CHECKED_IN_SCHEMA).expect("checked-in schema must be valid JSON");

    assert_eq!(
        checked_in, generated,
        "schema drifted; run `cargo run -p codeischeap-capture-ipc --bin export-capture-schema -- schemas/capture-envelope/v0.1.schema.json`"
    );
}
