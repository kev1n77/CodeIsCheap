use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, Response};
use codeischeap_adapters::{AdapterRegistry, OPENAI_ADAPTER_ID};
use codeischeap_capture_ipc::CaptureSource;
use codeischeap_capture_policy::CapturePolicy;
use codeischeap_core::{GatewayCaptureOutcome, process_gateway_event};
use codeischeap_desktop_api::load_workspace;
use codeischeap_gateway::{Gateway, GatewayCapture, GatewayCaptureEvent};
use codeischeap_storage::{DatabaseKey, EncryptedStore};
use serde_json::json;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

struct TestServer {
    base_url: Url,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn(router: Router) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener must bind");
    let address = listener
        .local_addr()
        .expect("listener must have an address");
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("test server must run");
    });
    TestServer {
        base_url: Url::parse(&format!("http://{address}")).expect("test URL must parse"),
        task,
    }
}

#[derive(Clone, Default)]
struct ProviderProbe {
    request: Arc<Mutex<Option<ObservedRequest>>>,
}

struct ObservedRequest {
    authorization: String,
    query: String,
    body: Vec<u8>,
}

async fn fake_openai(State(probe): State<ProviderProbe>, request: Request<Body>) -> Response<Body> {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let body = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("provider request body must be readable")
        .to_vec();
    *probe.request.lock().expect("probe lock must be healthy") = Some(ObservedRequest {
        authorization,
        query,
        body,
    });
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(r#"{"id":"response_1","status":"completed"}"#))
        .expect("provider response must build")
}

#[tokio::test]
async fn gateway_request_reaches_openai_adapter_sqlcipher_and_desktop_api() {
    const HEADER_SECRET: &str = "gateway-header-canary";
    const QUERY_SECRET: &str = "gateway-query-canary";
    const BODY_SECRET: &str = "gateway-body-canary";
    const NESTED_SECRET: &str = "gateway-nested-canary";
    const PROMPT: &str = "Explain why the streaming parser test fails.";

    let probe = ProviderProbe::default();
    let upstream = spawn(
        Router::new()
            .fallback(fake_openai)
            .with_state(probe.clone()),
    )
    .await;
    let (capture, mut receiver, metrics) =
        GatewayCapture::channel(1, 64 * 1024).expect("capture must build");
    let gateway = Gateway::new(upstream.base_url.clone())
        .expect("gateway must build")
        .with_capture(capture);
    let gateway = spawn(gateway.router()).await;
    let request_body = json!({
        "model": "gpt-5.2",
        "instructions": "Answer with repository evidence.",
        "input": [{
            "role": "user",
            "content": [{"type": "input_text", "text": PROMPT}]
        }],
        "password": BODY_SECRET,
        "metadata": {"token": NESTED_SECRET},
        "stream": true
    });
    let encoded_request = serde_json::to_vec(&request_body).expect("request must encode");
    let target = gateway
        .base_url
        .join(&format!("/v1/responses?api-key={QUERY_SECRET}"))
        .expect("target URL must build");

    let response = reqwest::Client::new()
        .post(target)
        .header("authorization", format!("Bearer {HEADER_SECRET}"))
        .header("content-type", "application/json")
        .body(encoded_request.clone())
        .send()
        .await
        .expect("gateway request must succeed")
        .bytes()
        .await
        .expect("gateway response must be readable");
    assert_eq!(
        response.as_ref(),
        br#"{"id":"response_1","status":"completed"}"#
    );

    let observed = probe
        .request
        .lock()
        .expect("probe lock must be healthy")
        .take()
        .expect("provider must observe the request");
    assert_eq!(observed.authorization, format!("Bearer {HEADER_SECRET}"));
    assert_eq!(observed.query, format!("api-key={QUERY_SECRET}"));
    assert_eq!(observed.body, encoded_request);
    assert_eq!(metrics.snapshot().dropped_queue_full, 1);

    let event = receiver.recv().await.expect("request capture must arrive");
    assert!(matches!(event, GatewayCaptureEvent::Request(_)));
    let directory = tempdir().expect("temp directory must be created");
    let database_path = directory.path().join("captures.db");
    let mut store = EncryptedStore::open(&database_path, DatabaseKey::from_bytes([0x62; 32]))
        .expect("encrypted store must open");
    let policy = test_policy(
        upstream
            .base_url
            .host_str()
            .expect("upstream must have a host"),
    );
    let outcome = process_gateway_event(&mut store, &policy, &AdapterRegistry::default(), event)
        .expect("gateway capture must persist");
    let GatewayCaptureOutcome::Persisted(outcome) = outcome else {
        panic!("request event must produce a persisted outcome");
    };
    assert_eq!(outcome.adapter_id.as_deref(), Some(OPENAI_ADAPTER_ID));
    assert!(!outcome.raw_fallback);

    let stored = store
        .get_capture(&outcome.capture_id)
        .expect("capture query must succeed")
        .expect("capture must exist");
    assert_eq!(stored.envelope.source, CaptureSource::Gateway);
    assert_eq!(stored.envelope.redactions.len(), 4);
    assert!(stored.prompt_ir.is_some());
    let stored_json = serde_json::to_string(&(&stored.envelope, &stored.prompt_ir))
        .expect("stored capture must encode");
    assert!(!stored_json.contains(HEADER_SECRET));
    assert!(!stored_json.contains(QUERY_SECRET));
    assert!(!stored_json.contains(BODY_SECRET));
    assert!(!stored_json.contains(NESTED_SECRET));
    assert!(stored_json.contains(PROMPT));

    let workspace = load_workspace(&store).expect("desktop workspace must load");
    assert_eq!(workspace.capture.request_count, 1);
    assert_eq!(workspace.requests[0].provider, "OpenAI");
    assert_eq!(workspace.requests[0].prompt_preview, PROMPT);
    let workspace_json = serde_json::to_string(&workspace).expect("desktop workspace must encode");
    for secret in [HEADER_SECRET, QUERY_SECRET, BODY_SECRET, NESTED_SECRET] {
        assert!(!workspace_json.contains(secret));
        assert_file_excludes(&database_path, secret);
        assert_file_excludes(&database_path.with_extension("db-wal"), secret);
    }
}

fn test_policy(host: &str) -> CapturePolicy {
    CapturePolicy::from_json(
        &json!({
            "version": "0.1",
            "targets": [{
                "id": "openai",
                "hosts": [host],
                "methods": ["POST"],
                "paths": ["/v1/responses"]
            }],
            "sensitive_names": ["authorization", "api-key", "password", "token"]
        })
        .to_string(),
    )
    .expect("test policy must be valid")
}

fn assert_file_excludes(path: &Path, secret: &str) {
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    assert!(
        !bytes
            .windows(secret.len())
            .any(|window| window == secret.as_bytes()),
        "{} must not contain plaintext secret",
        path.display()
    );
}
