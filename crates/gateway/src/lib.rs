//! Streaming reverse proxy used by the local CodeIsCheap AI Gateway.

use std::collections::HashSet;
use std::future::Future;
use std::io;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{
    CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
    UPGRADE,
};
use axum::http::{HeaderMap, HeaderName, Request, Response, StatusCode, Uri};
use futures_util::TryStreamExt;
use reqwest::redirect::Policy;
use tokio::net::TcpListener;
use url::Url;

const ERROR_HEADER: &str = "x-codeischeap-error";

#[derive(Debug, Clone)]
pub struct Gateway {
    client: reqwest::Client,
    upstream: Url,
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

        Ok(Self { client, upstream })
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
    let (parts, body) = request.into_parts();
    let target = gateway
        .target_url(&parts.uri)
        .map_err(ForwardError::InvalidTarget)?;
    let headers = sanitized_headers(&parts.headers);
    let body = reqwest::Body::wrap_stream(body.into_data_stream().map_err(io::Error::other));

    let upstream = gateway
        .client
        .request(parts.method, target)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(ForwardError::Upstream)?;

    let status = upstream.status();
    let version = upstream.version();
    let headers = sanitized_headers(upstream.headers());
    let body = Body::from_stream(upstream.bytes_stream().map_err(io::Error::other));

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
