use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use codeischeap_gateway::{Gateway, GatewayCapture};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

const WARMUP_REQUESTS: usize = 20;
const MEASURED_REQUESTS: usize = 200;
const MAX_GATEWAY_OVERHEAD_P95: Duration = Duration::from_millis(20);

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
        .expect("benchmark listener must bind");
    let address = listener.local_addr().expect("benchmark address must exist");
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("benchmark server must run");
    });
    TestServer {
        base_url: Url::parse(&format!("http://{address}")).expect("benchmark URL must parse"),
        task,
    }
}

async fn fake_provider() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"output_text":"ok"}"#))
        .expect("fake provider response must build")
}

async fn request_latency(client: &reqwest::Client, url: Url) -> Duration {
    let started = Instant::now();
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .body(r#"{"model":"benchmark","input":"hello"}"#)
        .send()
        .await
        .expect("benchmark request must succeed");
    assert_eq!(response.status(), StatusCode::OK);
    response
        .bytes()
        .await
        .expect("benchmark response must be readable");
    started.elapsed()
}

fn percentile(samples: &mut [Duration], percentile: usize) -> Duration {
    samples.sort_unstable();
    let rank = samples
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1);
    samples[rank.min(samples.len().saturating_sub(1))]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "performance gate; run explicitly in serialized CI"]
async fn gateway_capture_overhead_p95_stays_below_twenty_milliseconds() {
    let upstream = spawn(Router::new().fallback(fake_provider)).await;
    let (capture, mut receiver, metrics) = GatewayCapture::defaults();
    let drain = tokio::spawn(async move { while receiver.recv().await.is_some() {} });
    let gateway = Gateway::new(upstream.base_url.clone())
        .expect("gateway must build")
        .with_capture(capture);
    let gateway = spawn(gateway.router()).await;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(4)
        .build()
        .expect("benchmark client must build");

    for _ in 0..WARMUP_REQUESTS {
        request_latency(&client, upstream.base_url.clone()).await;
        request_latency(&client, gateway.base_url.clone()).await;
    }

    let mut direct = Vec::with_capacity(MEASURED_REQUESTS);
    let mut proxied = Vec::with_capacity(MEASURED_REQUESTS);
    for index in 0..MEASURED_REQUESTS {
        if index % 2 == 0 {
            direct.push(request_latency(&client, upstream.base_url.clone()).await);
            proxied.push(request_latency(&client, gateway.base_url.clone()).await);
        } else {
            proxied.push(request_latency(&client, gateway.base_url.clone()).await);
            direct.push(request_latency(&client, upstream.base_url.clone()).await);
        }
    }

    let direct_p95 = percentile(&mut direct, 95);
    let gateway_p95 = percentile(&mut proxied, 95);
    let overhead_p95 = gateway_p95.saturating_sub(direct_p95);
    let snapshot = metrics.snapshot();
    println!(
        "gateway_latency direct_p95_us={} gateway_p95_us={} overhead_p95_us={} samples={}",
        direct_p95.as_micros(),
        gateway_p95.as_micros(),
        overhead_p95.as_micros(),
        MEASURED_REQUESTS,
    );

    assert_eq!(snapshot.dropped_queue_full, 0);
    assert_eq!(snapshot.dropped_receiver_closed, 0);
    assert!(
        overhead_p95 < MAX_GATEWAY_OVERHEAD_P95,
        "Gateway P95 overhead was {overhead_p95:?}, limit is {MAX_GATEWAY_OVERHEAD_P95:?}"
    );

    drop(gateway);
    drain.abort();
}
