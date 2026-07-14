use std::convert::Infallible;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use bytes::Bytes;
use codeischeap_gateway::Gateway;
use futures_util::{StreamExt, stream};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
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

async fn spawn_gateway(upstream: Url) -> TestServer {
    let gateway = Gateway::new(upstream).expect("gateway must build");
    spawn(gateway.router()).await
}

async fn echo(request: Request<Body>) -> Response<Body> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let forwarded = request
        .headers()
        .get("x-forwarded-test")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("missing")
        .to_owned();
    let removed = request.headers().contains_key("x-remove-me");
    let body = to_bytes(request.into_body(), 1024)
        .await
        .expect("body must be readable");

    Response::builder()
        .status(StatusCode::CREATED)
        .header("x-upstream", "present")
        .header("connection", "x-upstream-remove")
        .header("x-upstream-remove", "secret")
        .body(Body::from(format!(
            "{method} {uri} {forwarded} removed={removed} body={}",
            String::from_utf8_lossy(&body)
        )))
        .expect("response must build")
}

#[tokio::test]
async fn forwards_request_and_response_without_hop_by_hop_headers() {
    let upstream = spawn(Router::new().fallback(echo)).await;
    let gateway = spawn_gateway(upstream.base_url.clone()).await;
    let target = gateway
        .base_url
        .join("/v1/messages?stream=true")
        .expect("target URL must build");

    let response = reqwest::Client::new()
        .post(target)
        .header("x-forwarded-test", "present")
        .header("connection", "x-remove-me")
        .header("x-remove-me", "secret")
        .body("hello")
        .send()
        .await
        .expect("request must succeed");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers().get("x-upstream").unwrap(), "present");
    assert!(!response.headers().contains_key("x-upstream-remove"));
    assert_eq!(
        response
            .text()
            .await
            .expect("response body must be readable"),
        "POST /v1/messages?stream=true present removed=false body=hello"
    );
}

async fn streaming_response() -> Response<Body> {
    let chunks = stream::unfold(0_u8, |state| async move {
        match state {
            0 => Some((Ok::<_, Infallible>(Bytes::from_static(b"first")), 1)),
            1 => {
                sleep(Duration::from_millis(400)).await;
                Some((Ok(Bytes::from_static(b"second")), 2))
            }
            _ => None,
        }
    });
    Response::new(Body::from_stream(chunks))
}

#[tokio::test]
async fn forwards_response_chunks_before_the_upstream_stream_finishes() {
    let upstream = spawn(Router::new().fallback(streaming_response)).await;
    let gateway = spawn_gateway(upstream.base_url.clone()).await;
    let response = reqwest::get(gateway.base_url.clone())
        .await
        .expect("request must succeed");
    let mut chunks = response.bytes_stream();

    let first = timeout(Duration::from_millis(200), chunks.next())
        .await
        .expect("first chunk must arrive before the delayed second chunk")
        .expect("stream must contain a first chunk")
        .expect("first chunk must be readable");
    assert_eq!(first, "first");

    let second = timeout(Duration::from_secs(1), chunks.next())
        .await
        .expect("second chunk must arrive")
        .expect("stream must contain a second chunk")
        .expect("second chunk must be readable");
    assert_eq!(second, "second");
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
async fn propagates_downstream_cancellation_to_the_upstream_body() {
    let probe = CancellationProbe::default();
    let upstream = spawn(
        Router::new()
            .fallback(cancellable_response)
            .with_state(probe.clone()),
    )
    .await;
    let gateway = spawn_gateway(upstream.base_url.clone()).await;
    let response = reqwest::get(gateway.base_url.clone())
        .await
        .expect("request must succeed");
    let mut chunks = response.bytes_stream();

    let first = timeout(Duration::from_secs(1), chunks.next())
        .await
        .expect("first chunk must arrive")
        .expect("stream must contain a first chunk")
        .expect("first chunk must be readable");
    assert_eq!(first, "first");
    drop(chunks);

    timeout(
        Duration::from_secs(2),
        probe.upstream_body_dropped.notified(),
    )
    .await
    .expect("dropping the downstream stream must release the upstream body");
}

#[derive(Clone, Default)]
struct RequestProbe {
    first_chunk_seen: Arc<Notify>,
}

async fn observe_streamed_request(State(probe): State<RequestProbe>, body: Body) -> String {
    let mut chunks = body.into_data_stream();
    let first = chunks
        .next()
        .await
        .expect("request must contain a first chunk")
        .expect("first chunk must be readable");
    probe.first_chunk_seen.notify_one();

    let mut received = first.to_vec();
    while let Some(chunk) = chunks.next().await {
        received.extend_from_slice(&chunk.expect("remaining chunk must be readable"));
    }
    String::from_utf8(received).expect("test body must be UTF-8")
}

#[tokio::test]
async fn forwards_request_chunks_before_the_client_stream_finishes() {
    let probe = RequestProbe::default();
    let upstream = spawn(
        Router::new()
            .fallback(observe_streamed_request)
            .with_state(probe.clone()),
    )
    .await;
    let gateway = spawn_gateway(upstream.base_url.clone()).await;
    let (sender, receiver) = mpsc::channel::<Result<Bytes, io::Error>>(2);
    let body = reqwest::Body::wrap_stream(ReceiverStream::new(receiver));
    let target = gateway.base_url.clone();
    let request = tokio::spawn(async move {
        reqwest::Client::new()
            .post(target)
            .body(body)
            .send()
            .await
            .expect("request must succeed")
            .text()
            .await
            .expect("response must be readable")
    });

    sender
        .send(Ok(Bytes::from_static(b"first")))
        .await
        .expect("first chunk must send");
    timeout(
        Duration::from_millis(200),
        probe.first_chunk_seen.notified(),
    )
    .await
    .expect("upstream must see the first chunk before the request finishes");
    sender
        .send(Ok(Bytes::from_static(b"second")))
        .await
        .expect("second chunk must send");
    drop(sender);

    assert_eq!(
        request.await.expect("request task must complete"),
        "firstsecond"
    );
}

#[tokio::test]
async fn returns_a_stable_bad_gateway_error_for_unreachable_upstreams() {
    let upstream = Url::parse("http://127.0.0.1:9").expect("URL must parse");
    let gateway = spawn_gateway(upstream).await;
    let response = reqwest::get(gateway.base_url.clone())
        .await
        .expect("gateway must return a response");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.headers().get("x-codeischeap-error").unwrap(),
        "upstream_unavailable"
    );
    assert_eq!(
        response.text().await.expect("error body must be readable"),
        "AI upstream request failed"
    );
}
