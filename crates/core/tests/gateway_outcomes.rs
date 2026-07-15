use codeischeap_adapters::AdapterRegistry;
use codeischeap_capture_ipc::{CaptureOutcome, CapturedBodyState, ResponseCompleteness};
use codeischeap_capture_policy::CapturePolicy;
use codeischeap_core::{GatewayCaptureOutcome, process_gateway_event};
use codeischeap_desktop_api::{CaptureStatus, load_workspace};
use codeischeap_gateway::{
    CapturedPayload, GatewayCaptureEvent, GatewayRequestCapture, GatewayResponseCapture,
    GatewayUpstreamFailure,
};
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
