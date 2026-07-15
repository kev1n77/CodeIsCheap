//! Streaming reverse proxy used by the local CodeIsCheap AI Gateway.

mod capture;

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, HttpBody};
use axum::extract::State;
use axum::http::header::{
    CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
    UPGRADE,
};
use axum::http::{HeaderMap, HeaderName, Request, Response, StatusCode, Uri};
use futures_util::{StreamExt, TryStreamExt};
use reqwest::redirect::Policy;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use url::Url;
use uuid::Uuid;

pub use capture::{
    CaptureConfigError, CaptureMetricSnapshot, CaptureMetrics, CapturedPayload,
    DEFAULT_CAPTURE_BODY_LIMIT, DEFAULT_CAPTURE_QUEUE_CAPACITY, GatewayCapture,
    GatewayCaptureEvent, GatewayRequestCapture, GatewayResponseCapture, GatewayUpstreamFailure,
};

use capture::{RequestCaptureGuard, RequestMetadata, ResponseCaptureGuard, ResponseMetadata};

const ERROR_HEADER: &str = "x-codeischeap-error";
const REQUEST_FORWARD_QUEUE_CAPACITY: usize = 8;

#[derive(Debug, Clone)]
pub struct Gateway {
    client: reqwest::Client,
    upstream: Url,
    capture: Option<GatewayCapture>,
}

#[derive(Debug)]
pub enum GatewayBuildError {
    UnsupportedScheme(String),
    UpstreamContainsQuery,
    UpstreamContainsFragment,
    Client(reqwest::Error),
}

impl std::fmt::Display for GatewayBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedScheme(scheme) => {
                write!(formatter, "unsupported upstream URL scheme: {scheme}")
            }
            Self::UpstreamContainsQuery => {
                write!(formatter, "upstream URL must not contain a query")
            }
            Self::UpstreamContainsFragment => {
                write!(formatter, "upstream URL must not contain a fragment")
            }
            Self::Client(error) => write!(formatter, "failed to build HTTP client: {error}"),
        }
    }
}

impl std::error::Error for GatewayBuildError {}

impl Gateway {
    pub fn new(upstream: Url) -> Result<Self, GatewayBuildError> {
        if !matches!(upstream.scheme(), "http" | "https") {
            return Err(GatewayBuildError::UnsupportedScheme(
                upstream.scheme().to_owned(),
            ));
        }
        if upstream.query().is_some() {
            return Err(GatewayBuildError::UpstreamContainsQuery);
        }
        if upstream.fragment().is_some() {
            return Err(GatewayBuildError::UpstreamContainsFragment);
        }

        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .map_err(GatewayBuildError::Client)?;

        Ok(Self {
            client,
            upstream,
            capture: None,
        })
    }

    #[must_use]
    pub fn with_capture(mut self, capture: GatewayCapture) -> Self {
        self.capture = Some(capture);
        self
    }

    pub fn router(self) -> Router {
        Router::new().fallback(forward).with_state(self)
    }

    pub async fn serve<F>(self, listener: TcpListener, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        axum::serve(listener, self.router())
            .with_graceful_shutdown(shutdown)
            .await
    }

    fn target_url(&self, uri: &Uri) -> Result<Url, url::ParseError> {
        let base = self.upstream.as_str().trim_end_matches('/');
        let mut target = String::with_capacity(base.len() + uri.path().len() + 1);
        target.push_str(base);
        if !uri.path().starts_with('/') {
            target.push('/');
        }
        target.push_str(uri.path());
        if let Some(query) = uri.query() {
            target.push('?');
            target.push_str(query);
        }
        Url::parse(&target)
    }
}

async fn forward(State(gateway): State<Gateway>, request: Request<Body>) -> Response<Body> {
    match forward_to_upstream(&gateway, request).await {
        Ok(response) => response,
        Err(error) => error_response(error),
    }
}

async fn forward_to_upstream(
    gateway: &Gateway,
    request: Request<Body>,
) -> Result<Response<Body>, ForwardError> {
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let target = gateway
        .target_url(&parts.uri)
        .map_err(ForwardError::InvalidTarget)?;
    let capture_id = gateway
        .capture
        .as_ref()
        .filter(|capture| capture.is_enabled())
        .map(|_| Uuid::new_v4().to_string());
    let body =
        if let (Some(capture), Some(capture_id)) = (gateway.capture.clone(), capture_id.clone()) {
            let metadata = RequestMetadata {
                capture_id,
                observed_at_unix_ms: unix_time_ms(),
                method: parts.method.as_str().to_owned(),
                scheme: target.scheme().to_owned(),
                host: target.host_str().unwrap_or_default().to_owned(),
                port: target.port_or_known_default().unwrap_or_default(),
                path: target.path().to_owned(),
                query: target
                    .query_pairs()
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect(),
                headers: header_fields(&parts.headers),
            };
            let expected_body_bytes =
                content_length(&parts.headers).or_else(|| body.size_hint().exact());
            let mut chunks = body.into_data_stream();
            let mut guard = RequestCaptureGuard::new(capture, metadata, expected_body_bytes);
            let (sender, receiver) =
                mpsc::channel::<Result<bytes::Bytes, io::Error>>(REQUEST_FORWARD_QUEUE_CAPACITY);
            tokio::spawn(async move {
                while let Some(result) = chunks.next().await {
                    match result {
                        Ok(chunk) => {
                            guard.push(&chunk);
                            if sender.send(Ok(chunk)).await.is_err() {
                                return;
                            }
                        }
                        Err(error) => {
                            let _ = sender.send(Err(io::Error::other(error))).await;
                            return;
                        }
                    }
                }
                guard.complete();
            });
            reqwest::Body::wrap_stream(ReceiverStream::new(receiver))
        } else {
            reqwest::Body::wrap_stream(body.into_data_stream().map_err(io::Error::other))
        };
    let headers = sanitized_headers(&parts.headers);

    let upstream = match gateway
        .client
        .request(parts.method, target)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            if let (Some(capture), Some(capture_id)) = (&gateway.capture, capture_id) {
                capture.emit(GatewayCaptureEvent::UpstreamFailure(
                    GatewayUpstreamFailure {
                        capture_id,
                        duration_ms: capture::elapsed_ms(started),
                    },
                ));
            }
            return Err(ForwardError::Upstream(error));
        }
    };

    let status = upstream.status();
    let version = upstream.version();
    let expected_body_bytes = upstream.content_length();
    let captured_headers = header_fields(upstream.headers());
    let headers = sanitized_headers(upstream.headers());
    let body = if let (Some(capture), Some(capture_id)) = (gateway.capture.clone(), capture_id) {
        let metadata = ResponseMetadata {
            capture_id,
            status: status.as_u16(),
            headers: captured_headers,
            started,
        };
        let mut chunks = upstream.bytes_stream();
        let mut guard = ResponseCaptureGuard::new(capture, metadata, expected_body_bytes);
        Body::from_stream(async_stream::stream! {
            while let Some(result) = chunks.next().await {
                match result {
                    Ok(chunk) => {
                        guard.push(&chunk);
                        yield Ok::<_, io::Error>(chunk);
                    }
                    Err(error) => {
                        yield Err(io::Error::other(error));
                        return;
                    }
                }
            }
            guard.complete();
        })
    } else {
        Body::from_stream(upstream.bytes_stream().map_err(io::Error::other))
    };

    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.version_mut() = version;
    *response.headers_mut() = headers;
    Ok(response)
}

#[derive(Debug)]
enum ForwardError {
    InvalidTarget(url::ParseError),
    Upstream(reqwest::Error),
}

fn error_response(error: ForwardError) -> Response<Body> {
    let error_code = match error {
        ForwardError::InvalidTarget(error) => {
            let _ = error;
            "invalid_target"
        }
        ForwardError::Upstream(error) => {
            let _ = error;
            "upstream_unavailable"
        }
    };

    let mut response = Response::new(Body::from("AI upstream request failed"));
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response.headers_mut().insert(
        HeaderName::from_static(ERROR_HEADER),
        http::HeaderValue::from_static(error_code),
    );
    response
}

fn sanitized_headers(headers: &HeaderMap) -> HeaderMap {
    let mut blocked = connection_header_names(headers);
    blocked.extend([
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        HOST,
    ]);

    headers
        .iter()
        .filter(|(name, _)| !blocked.contains(*name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn connection_header_names(headers: &HeaderMap) -> HashSet<HeaderName> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect()
}

fn header_fields(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}
