use codeischeap_adapters::AdapterRegistry;
use codeischeap_capture_ipc::{CaptureOutcome, CapturedBodyState, ResponseCompleteness};
use codeischeap_capture_policy::CapturePolicy;
use codeischeap_core::{GatewayCaptureOutcome, process_gateway_event};
use codeischeap_desktop_api::{CaptureStatus, EvidenceLocator, load_workspace};
use codeischeap_gateway::{
    CapturedPayload, GatewayCaptureEvent, GatewayRequestCapture, GatewayResponseCapture,
    GatewayUpstreamFailure,
};
use codeischeap_prompt_ir::{BodyState, PromptPart};
use codeischeap_storage::{DatabaseKey, EncryptedStore};
use tempfile::tempdir;

fn request_event(capture_id: &str) -> GatewayCaptureEvent {
    GatewayCaptureEvent::Request(GatewayRequestCapture {
        capture_id: capture_id.to_owned(),
        observed_at_unix_ms: 1_784_073_000_000,
        method: "POST".to_owned(),
        scheme: "https".to_owned(),
        host: "api.openai.com".to_owned(),
        port: 443,
        path: "/v1/responses".to_owned(),
        query: Vec::new(),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: CapturedPayload {
            bytes: br#"{"model":"gpt-5","input":"inspect the outcome"}"#.to_vec().into(),
            truncated: false,
            complete: true,
        },
    })
}

fn anthropic_request_event(capture_id: &str) -> GatewayCaptureEvent {
    GatewayCaptureEvent::Request(GatewayRequestCapture {
        capture_id: capture_id.to_owned(),
        observed_at_unix_ms: 1_784_073_100_000,
        method: "POST".to_owned(),
        scheme: "https".to_owned(),
        host: "api.anthropic.com".to_owned(),
        port: 443,
        path: "/v1/messages".to_owned(),
        query: Vec::new(),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: CapturedPayload {
            bytes: br#"{"model":"claude-sonnet-4-5","max_tokens":128,"messages":[{"role":"user","content":"Read Cargo.toml"}],"tools":[{"name":"read_file","input_schema":{"type":"object"}}],"stream":true}"#
                .to_vec()
                .into(),
            truncated: false,
            complete: true,
        },
    })
}

fn ollama_request_event(capture_id: &str) -> GatewayCaptureEvent {
    GatewayCaptureEvent::Request(GatewayRequestCapture {
        capture_id: capture_id.to_owned(),
        observed_at_unix_ms: 1_784_073_200_000,
        method: "POST".to_owned(),
        scheme: "http".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: 11434,
        path: "/api/generate".to_owned(),
        query: Vec::new(),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: CapturedPayload {
            bytes: br#"{"model":"gemma3:4b","prompt":"Name this product","stream":true}"#
                .to_vec()
                .into(),
            truncated: false,
            complete: true,
        },
    })
}

fn response_event(
    capture_id: &str,
    status: u16,
    content_type: &str,
    body: &[u8],
    complete: bool,
) -> GatewayCaptureEvent {
    GatewayCaptureEvent::Response(GatewayResponseCapture {
        capture_id: capture_id.to_owned(),
        status,
        headers: vec![("content-type".to_owned(), content_type.to_owned())],
        duration_ms: 64,
        body: CapturedPayload {
            bytes: body.to_vec().into(),
            truncated: false,
            complete,
        },
    })
}

fn store() -> (tempfile::TempDir, EncryptedStore) {
    let directory = tempdir().expect("temp directory must be created");
    let store = EncryptedStore::open(
        directory.path().join("captures.db"),
        DatabaseKey::from_bytes([0x73; 32]),
    )
    .expect("encrypted store must open");
    (directory, store)
}

fn process(store: &mut EncryptedStore, event: GatewayCaptureEvent) -> GatewayCaptureOutcome {
    process_gateway_event(
        store,
        &CapturePolicy::load_default().expect("policy must load"),
        &AdapterRegistry::default(),
        event,
    )
    .expect("event must process")
}

#[test]
fn sse_response_is_persisted_as_text_and_exposed_in_raw_view() {
    let (_directory, mut store) = store();
    let capture_id = "sse_response";
    process(&mut store, request_event(capture_id));
    let outcome = process(
        &mut store,
        response_event(
            capture_id,
            200,
            "text/event-stream; charset=utf-8",
            b"event: message\ndata: {\"type\":\"done\"}\n\n",
            true,
        ),
    );

    let GatewayCaptureOutcome::ResponseObserved(observed) = outcome else {
        panic!("response event must be observed");
    };
    assert!(observed.persisted);
    let stored = store
        .get_capture(capture_id)
        .expect("capture query must succeed")
        .expect("capture must exist");
    let CaptureOutcome::Response(response) = stored.envelope.outcome.expect("outcome must exist")
    else {
        panic!("outcome must be a response");
    };
    assert_eq!(response.body.state, CapturedBodyState::Text);
    assert_eq!(response.completeness, ResponseCompleteness::Complete);
    assert!(
        response
            .body
            .content
            .expect("text body must exist")
            .as_str()
            .expect("text body must be a string")
            .contains("done")
    );

    let workspace = load_workspace(&store).expect("workspace must load");
    assert_eq!(workspace.requests[0].status, CaptureStatus::Complete);
    assert_eq!(workspace.requests[0].duration_ms, Some(64));
    assert!(
        workspace.requests[0]
            .detail
            .raw
            .to_string()
            .contains("done")
    );
}

#[test]
fn ollama_ndjson_reaches_encrypted_storage_and_exact_desktop_timeline_ranges() {
    let (_directory, mut store) = store();
    let capture_id = "ollama_ndjson";
    process(&mut store, ollama_request_event(capture_id));
    let first_line = r#"{"model":"gemma3:4b","response":"CodeIs","done":false}"#;
    let response = format!(
        "{first_line}\n{{\"model\":\"gemma3:4b\",\"response\":\"Cheap\",\"done\":false}}\n{{\"model\":\"gemma3:4b\",\"response\":\"\",\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":4,\"eval_count\":2}}\n"
    );
    process(
        &mut store,
        response_event(
            capture_id,
            200,
            "application/x-ndjson",
            response.as_bytes(),
            true,
        ),
    );

    let stored = store
        .get_capture(capture_id)
        .expect("capture query must succeed")
        .expect("capture must exist");
    let prompt = stored.prompt_ir.expect("Ollama Prompt IR must persist");
    assert_eq!(prompt.provider.id, "ollama");
    assert_eq!(prompt.model.as_deref(), Some("gemma3:4b"));
    assert!(matches!(
        &prompt.response.as_ref().expect("response must exist").parts[0],
        PromptPart::Text { text, .. } if text == "CodeIsCheap"
    ));

    let workspace = load_workspace(&store).expect("workspace must load");
    let request = &workspace.requests[0];
    assert_eq!(request.provider, "Ollama");
    assert_eq!(request.model, "gemma3:4b");
    let event = request
        .detail
        .timeline
        .iter()
        .find(|event| event.id == "response_stream_0")
        .expect("first Ollama chunk must reach the timeline");
    let EvidenceLocator::TextRange {
        pointer,
        start,
        end,
    } = event
        .locator
        .as_ref()
        .expect("chunk must locate raw evidence")
    else {
        panic!("Ollama chunk must use a text range");
    };
    assert_eq!(pointer, "/outcome/result/body/content");
    let raw_text = request
        .detail
        .raw
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .expect("raw NDJSON must remain text");
    let fragment = &raw_text.as_bytes()[usize::try_from(*start).expect("start must fit")
        ..usize::try_from(*end).expect("end must fit")];
    assert_eq!(
        std::str::from_utf8(fragment).expect("range must be UTF-8"),
        first_line
    );
}

#[test]
fn http_errors_and_upstream_failures_are_exposed_as_errors() {
    let (_directory, mut store) = store();
    process(&mut store, request_event("http_error"));
    process(
        &mut store,
        response_event(
            "http_error",
            429,
            "application/json",
            br#"{"error":{"message":"rate limited"}}"#,
            true,
        ),
    );
    process(&mut store, request_event("upstream_failure"));
    let failure = process(
        &mut store,
        GatewayCaptureEvent::UpstreamFailure(GatewayUpstreamFailure {
            capture_id: "upstream_failure".to_owned(),
            duration_ms: 91,
        }),
    );
    let GatewayCaptureOutcome::UpstreamFailed(failure) = failure else {
        panic!("failure event must be observed");
    };
    assert!(failure.persisted);

    let workspace = load_workspace(&store).expect("workspace must load");
    let http = workspace
        .requests
        .iter()
        .find(|request| request.id == "http_error")
        .expect("HTTP error must be listed");
    assert_eq!(http.status, CaptureStatus::Error);
    assert_eq!(http.duration_ms, Some(64));
    assert!(http.detail.raw.to_string().contains("429"));
    let upstream = workspace
        .requests
        .iter()
        .find(|request| request.id == "upstream_failure")
        .expect("upstream failure must be listed");
    assert_eq!(upstream.status, CaptureStatus::Error);
    assert_eq!(upstream.duration_ms, Some(91));
    assert!(
        upstream
            .detail
            .timeline
            .iter()
            .any(|event| event.id == "upstream_failed")
    );
}

#[test]
fn interrupted_responses_are_final_errors_not_live_streams() {
    let (_directory, mut store) = store();
    let capture_id = "cancelled_response";
    process(&mut store, request_event(capture_id));
    process(
        &mut store,
        response_event(
            capture_id,
            200,
            "text/event-stream",
            b"data: partial\n\n",
            false,
        ),
    );

    let workspace = load_workspace(&store).expect("workspace must load");
    assert_eq!(workspace.requests[0].status, CaptureStatus::Error);
    assert!(
        workspace.requests[0]
            .detail
            .timeline
            .iter()
            .any(|event| event.title == "Response interrupted")
    );
    let stored = store
        .get_capture(capture_id)
        .expect("capture query must succeed")
        .expect("capture must exist");
    let CaptureOutcome::Response(response) = stored.envelope.outcome.expect("outcome must exist")
    else {
        panic!("outcome must be a response");
    };
    assert_eq!(response.completeness, ResponseCompleteness::Incomplete);
    assert_eq!(response.body.state, CapturedBodyState::Truncated);
}

#[test]
fn outcomes_can_be_replayed_after_an_out_of_order_request() {
    let (_directory, mut store) = store();
    let capture_id = "out_of_order";
    let response = response_event(
        capture_id,
        201,
        "application/json",
        br#"{"id":"created"}"#,
        true,
    );

    let first = process(&mut store, response.clone());
    let GatewayCaptureOutcome::ResponseObserved(first) = first else {
        panic!("response must be observed");
    };
    assert!(!first.persisted);
    process(&mut store, request_event(capture_id));
    let replayed = process(&mut store, response);
    let GatewayCaptureOutcome::ResponseObserved(replayed) = replayed else {
        panic!("response must be observed after replay");
    };
    assert!(replayed.persisted);
    assert!(
        store
            .get_capture(capture_id)
            .expect("capture query must succeed")
            .expect("capture must exist")
            .envelope
            .outcome
            .is_some()
    );
}

#[test]
fn anthropic_sse_is_reparsed_after_outcome_persistence_and_reaches_timeline() {
    let (_directory, mut store) = store();
    let capture_id = "anthropic_sse_core";
    process(&mut store, anthropic_request_event(capture_id));
    let sse = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_core\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-5\",\"content\":[],\"usage\":{\"input_tokens\":9}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_core\",\"name\":\"read_file\",\"input\":{}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\\\"Cargo.toml\\\"}\"}}\n\n",
        "event: content_block_stop\n",
        "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":7}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n"
    );

    process(
        &mut store,
        response_event(capture_id, 200, "text/event-stream", sse.as_bytes(), true),
    );

    let stored = store
        .get_capture(capture_id)
        .expect("capture query must succeed")
        .expect("capture must exist");
    let prompt = stored
        .prompt_ir
        .expect("Anthropic Prompt IR must be refreshed");
    assert_eq!(prompt.completeness.response_body, BodyState::Complete);
    let response = prompt.response.expect("response trace must be persisted");
    assert!(matches!(
        &response.parts[0],
        PromptPart::ToolUse { name, input, .. }
            if name == "read_file" && input == &serde_json::json!({"path": "Cargo.toml"})
    ));

    let workspace = load_workspace(&store).expect("workspace must load");
    let timeline = &workspace.requests[0].detail.timeline;
    let tool_start = timeline
        .iter()
        .find(|event| {
            event.title == "Content block started"
                && event.kind == "tool"
                && event.sequence == Some(1)
                && event.offset_ms.is_none()
        })
        .expect("tool start must reach the Timeline");
    let Some(EvidenceLocator::TextRange {
        pointer,
        start,
        end,
    }) = &tool_start.locator
    else {
        panic!("tool start must point to its raw SSE frame");
    };
    let response_text = workspace.requests[0]
        .detail
        .raw
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .expect("Timeline pointer must resolve to response text");
    let frame = &response_text.as_bytes()[usize::try_from(*start).expect("start must fit")
        ..usize::try_from(*end).expect("end must fit")];
    assert_eq!(
        std::str::from_utf8(frame).expect("frame must remain UTF-8"),
        concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_core\",\"name\":\"read_file\",\"input\":{}}}\n"
        )
    );
    assert!(
        timeline.iter().any(|event| {
            event.title == "Response stream complete" && event.sequence == Some(5)
        })
    );
}

#[test]
fn anthropic_sse_error_marks_the_desktop_capture_as_failed() {
    let (_directory, mut store) = store();
    let capture_id = "anthropic_sse_error";
    process(&mut store, anthropic_request_event(capture_id));
    let sse = "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n";

    process(
        &mut store,
        response_event(capture_id, 200, "text/event-stream", sse.as_bytes(), true),
    );

    let workspace = load_workspace(&store).expect("workspace must load");
    assert_eq!(workspace.requests[0].status, CaptureStatus::Error);
    assert!(
        workspace.requests[0]
            .detail
            .timeline
            .iter()
            .any(|event| event.title == "Response stream failed")
    );
    assert!(
        workspace.requests[0]
            .detail
            .timeline
            .iter()
            .any(|event| event.title == "Response stream error")
    );
}
