use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, Response};
use bytes::Bytes;
use codeischeap_gateway::{CaptureConfigError, Gateway, GatewayCapture, GatewayCaptureEvent};
use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{timeout, timeout_at};
use tokio_stream::wrappers::ReceiverStream;
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

async fn spawn_gateway(upstream: Url, capture: GatewayCapture) -> TestServer {
    let gateway = Gateway::new(upstream)
        .expect("gateway must build")
        .with_capture(capture);
    spawn(gateway.router()).await
}

async fn fixed_response(request: Request<Body>) -> Response<Body> {
    let body = to_bytes(request.into_body(), usize::MAX)
        .await
        .expect("request body must be readable");
    assert_eq!(body, "captured request");
    Response::builder()
        .header("x-provider", "fake")
        .body(Body::from("captured response"))
        .expect("response must build")
}

#[tokio::test]
async fn captures_exact_forwarded_request_and_response_bodies() {
    let upstream = spawn(Router::new().fallback(fixed_response)).await;
    let (capture, mut receiver, metrics) =
        GatewayCapture::channel(8, 1024).expect("capture must build");
    let gateway = spawn_gateway(upstream.base_url.clone(), capture).await;

    let response = reqwest::Client::new()
        .post(
            gateway
                .base_url
                .join("/v1/responses?stream=true")
                .expect("target URL must build"),
        )
        .header("authorization", "Bearer request-secret")
        .header("content-type", "application/json")
        .body("captured request")
        .send()
        .await
        .expect("request must succeed");
    assert_eq!(
        response.text().await.expect("response must be readable"),
        "captured response"
    );

    let request = receiver.recv().await.expect("request capture must arrive");
    let response = receiver.recv().await.expect("response capture must arrive");
    let GatewayCaptureEvent::Request(request) = request else {
        panic!("first event must be the request capture");
    };
    let GatewayCaptureEvent::Response(response) = response else {
        panic!("second event must be the response capture");
    };

    assert_eq!(request.capture_id, response.capture_id);
    assert_eq!(request.method, "POST");
    assert_eq!(request.scheme, "http");
    assert_eq!(request.host, "127.0.0.1");
    assert_eq!(request.path, "/v1/responses");
    assert_eq!(request.query, [("stream".to_owned(), "true".to_owned())]);
    assert!(
        request
            .headers
            .iter()
            .any(|(name, value)| { name == "authorization" && value == "Bearer request-secret" })
    );
    assert_eq!(request.body.bytes, "captured request");
    assert!(request.body.complete);
    assert!(!request.body.truncated);
    assert_eq!(response.body.bytes, "captured response");
    assert!(response.body.complete);
    assert!(!response.body.truncated);
    assert_eq!(metrics.snapshot().emitted_events, 2);
}

async fn echo_body(body: Body) -> Response<Body> {
    Response::new(body)
}

async fn empty_response(body: Body) -> Response<Body> {
    assert!(
        to_bytes(body, 1)
            .await
            .expect("empty body must be readable")
            .is_empty()
    );
    Response::new(Body::empty())
}

#[tokio::test]
async fn emits_events_for_empty_request_and_response_bodies() {
    let upstream = spawn(Router::new().fallback(empty_response)).await;
    let (capture, mut receiver, _) = GatewayCapture::channel(4, 1024).expect("capture must build");
    let gateway = spawn_gateway(upstream.base_url.clone(), capture).await;

    let response = reqwest::Client::new()
        .post(gateway.base_url.clone())
        .body(Vec::new())
        .send()
        .await
        .expect("request must succeed")
        .bytes()
        .await
        .expect("response must be readable");
    assert!(response.is_empty());

    for _ in 0..2 {
        let event = receiver.recv().await.expect("capture must arrive");
        let payload = match event {
            GatewayCaptureEvent::Request(event) => event.body,
            GatewayCaptureEvent::Response(event) => event.body,
            GatewayCaptureEvent::UpstreamFailure(_) => panic!("request must not fail"),
        };
        assert!(payload.bytes.is_empty());
        assert!(payload.complete);
        assert!(!payload.truncated);
    }
}

#[tokio::test]
async fn capture_can_pause_without_stopping_forwarding() {
    let upstream = spawn(Router::new().fallback(echo_body)).await;
    let (capture, mut receiver, metrics) =
        GatewayCapture::channel(4, 1024).expect("capture must build");
    capture.set_enabled(false);
    assert!(!capture.is_enabled());
    let gateway = spawn_gateway(upstream.base_url.clone(), capture.clone()).await;

    let paused_response = reqwest::Client::new()
        .post(gateway.base_url.clone())
        .body("paused")
        .send()
        .await
        .expect("paused request must succeed")
        .text()
        .await
        .expect("paused response must be readable");
    assert_eq!(paused_response, "paused");
    assert!(receiver.try_recv().is_err());
    assert_eq!(metrics.snapshot().emitted_events, 0);

    capture.set_enabled(true);
    assert!(capture.is_enabled());
    let resumed_response = reqwest::Client::new()
        .post(gateway.base_url.clone())
        .body("resumed")
        .send()
        .await
        .expect("resumed request must succeed")
        .text()
        .await
        .expect("resumed response must be readable");
    assert_eq!(resumed_response, "resumed");
    assert!(matches!(
        receiver.recv().await,
        Some(GatewayCaptureEvent::Request(_))
    ));
    assert!(matches!(
        receiver.recv().await,
        Some(GatewayCaptureEvent::Response(_))
    ));
}

#[tokio::test]
async fn forwards_full_bodies_while_capturing_only_the_bounded_prefix() {
    let upstream = spawn(Router::new().fallback(echo_body)).await;
    let (capture, mut receiver, metrics) =
        GatewayCapture::channel(8, 16).expect("capture must build");
    let gateway = spawn_gateway(upstream.base_url.clone(), capture).await;
    let full_body = vec![b'x'; 64 * 1024];

    let response = reqwest::Client::new()
        .post(gateway.base_url.clone())
        .body(full_body.clone())
        .send()
        .await
        .expect("request must succeed")
        .bytes()
        .await
        .expect("response must be readable");
    assert_eq!(response.as_ref(), full_body.as_slice());

    for _ in 0..2 {
        let event = receiver.recv().await.expect("capture must arrive");
        let payload = match event {
            GatewayCaptureEvent::Request(event) => event.body,
            GatewayCaptureEvent::Response(event) => event.body,
            GatewayCaptureEvent::UpstreamFailure(_) => panic!("request must not fail"),
        };
        assert_eq!(payload.bytes, Bytes::from_static(b"xxxxxxxxxxxxxxxx"));
        assert!(payload.truncated);
        assert!(payload.complete);
    }
    assert_eq!(metrics.snapshot().truncated_bodies, 2);
}

#[tokio::test]
async fn a_full_capture_queue_never_blocks_forwarding() {
    let upstream = spawn(Router::new().fallback(echo_body)).await;
    let (capture, mut receiver, metrics) =
        GatewayCapture::channel(1, 1024).expect("capture must build");
    let gateway = spawn_gateway(upstream.base_url.clone(), capture).await;

    let response = timeout(
        Duration::from_secs(2),
        reqwest::Client::new()
            .post(gateway.base_url.clone())
            .body("still forwarded")
            .send(),
    )
    .await
    .expect("capture pressure must not delay forwarding")
    .expect("request must succeed")
    .text()
    .await
    .expect("response must be readable");

    assert_eq!(response, "still forwarded");
    assert!(matches!(
        receiver.recv().await,
        Some(GatewayCaptureEvent::Request(_))
    ));
    assert_eq!(metrics.snapshot().dropped_queue_full, 1);
}

#[tokio::test]
async fn a_closed_capture_receiver_only_increments_metrics() {
    let upstream = spawn(Router::new().fallback(echo_body)).await;
    let (capture, receiver, metrics) =
        GatewayCapture::channel(2, 1024).expect("capture must build");
    drop(receiver);
    let gateway = spawn_gateway(upstream.base_url.clone(), capture).await;

    let response = reqwest::Client::new()
        .post(gateway.base_url.clone())
        .body("still forwarded")
        .send()
        .await
        .expect("request must succeed")
        .text()
        .await
        .expect("response must be readable");

    assert_eq!(response, "still forwarded");
    assert_eq!(metrics.snapshot().dropped_receiver_closed, 2);
}

#[tokio::test]
async fn captures_the_request_when_the_upstream_connection_fails() {
    let upstream = Url::parse("http://127.0.0.1:9").expect("URL must parse");
    let (capture, mut receiver, _) = GatewayCapture::channel(4, 1024).expect("capture must build");
    let gateway = spawn_gateway(upstream, capture).await;

    let response = reqwest::Client::new()
        .post(gateway.base_url.clone())
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-test","input":"preserve this request"}"#)
        .send()
        .await
        .expect("gateway must return a response");
    assert_eq!(response.status(), axum::http::StatusCode::BAD_GATEWAY);

    let mut request = None;
    let mut failure = None;
    for _ in 0..2 {
        match timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("capture event must arrive")
            .expect("capture channel must remain open")
        {
            GatewayCaptureEvent::Request(event) => request = Some(event),
            GatewayCaptureEvent::UpstreamFailure(event) => failure = Some(event),
            GatewayCaptureEvent::Response(_) => panic!("failed upstream must not emit a response"),
        }
    }

    let request = request.expect("failed upstream must retain the request capture");
    let failure = failure.expect("failed upstream must emit a failure event");
    assert_eq!(request.capture_id, failure.capture_id);
    assert_eq!(
        request.body.bytes,
        r#"{"model":"gpt-test","input":"preserve this request"}"#
    );
    assert!(request.body.complete);
    assert!(!request.body.truncated);
}

#[derive(Clone, Default)]
struct CancellationProbe {
    upstream_body_dropped: Arc<Notify>,
}

async fn cancellable_response(State(probe): State<CancellationProbe>) -> Response<Body> {
    let (sender, receiver) = mpsc::channel::<Result<Bytes, Infallible>>(1);
    sender
        .send(Ok(Bytes::from_static(b"first")))
        .await
        .expect("first chunk must send");
    tokio::spawn(async move {
        sender.closed().await;
        probe.upstream_body_dropped.notify_one();
    });
    Response::new(Body::from_stream(ReceiverStream::new(receiver)))
}

#[tokio::test]
async fn downstream_cancellation_emits_an_incomplete_response_capture() {
    let probe = CancellationProbe::default();
    let upstream = spawn(
        Router::new()
            .fallback(cancellable_response)
            .with_state(probe.clone()),
    )
    .await;
    let (capture, mut receiver, metrics) =
        GatewayCapture::channel(8, 1024).expect("capture must build");
    let gateway = spawn_gateway(upstream.base_url.clone(), capture).await;
    let response = reqwest::get(gateway.base_url.clone())
        .await
        .expect("request must succeed");
    let mut chunks = response.bytes_stream();
    assert_eq!(
        chunks
            .next()
            .await
            .expect("first chunk must arrive")
            .expect("first chunk must be readable"),
        "first"
    );
    drop(chunks);

    timeout(
        Duration::from_secs(2),
        probe.upstream_body_dropped.notified(),
    )
    .await
    .expect("cancellation must reach the upstream body");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let response = loop {
        let event = timeout_at(deadline, receiver.recv())
            .await
            .expect("incomplete capture must arrive")
            .expect("capture channel must remain open");
        if let GatewayCaptureEvent::Response(response) = event {
            break response;
        }
    };
    assert_eq!(response.body.bytes, "first");
    assert!(!response.body.complete);
    assert!(!response.body.truncated);
    assert_eq!(metrics.snapshot().incomplete_streams, 1);
}

#[test]
fn rejects_zero_capacity_and_zero_body_limits() {
    assert_eq!(
        GatewayCapture::channel(0, 1).expect_err("zero capacity must fail"),
        CaptureConfigError::ZeroQueueCapacity
    );
    assert_eq!(
        GatewayCapture::channel(1, 0).expect_err("zero body limit must fail"),
        CaptureConfigError::ZeroBodyLimit
    );
}
