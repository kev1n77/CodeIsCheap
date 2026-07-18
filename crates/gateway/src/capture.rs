use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::mpsc;

pub const DEFAULT_CAPTURE_QUEUE_CAPACITY: usize = 128;
pub const DEFAULT_CAPTURE_BODY_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct GatewayCapture {
    sender: mpsc::Sender<GatewayCaptureEvent>,
    max_body_bytes: usize,
    metrics: CaptureMetrics,
    enabled: Arc<AtomicBool>,
}

impl GatewayCapture {
    pub fn channel(
        capacity: usize,
        max_body_bytes: usize,
    ) -> Result<(Self, mpsc::Receiver<GatewayCaptureEvent>, CaptureMetrics), CaptureConfigError>
    {
        if capacity == 0 {
            return Err(CaptureConfigError::ZeroQueueCapacity);
        }
        if max_body_bytes == 0 {
            return Err(CaptureConfigError::ZeroBodyLimit);
        }
        let (sender, receiver) = mpsc::channel(capacity);
        let metrics = CaptureMetrics::default();
        Ok((
            Self {
                sender,
                max_body_bytes,
                metrics: metrics.clone(),
                enabled: Arc::new(AtomicBool::new(true)),
            },
            receiver,
            metrics,
        ))
    }

    pub fn defaults() -> (Self, mpsc::Receiver<GatewayCaptureEvent>, CaptureMetrics) {
        Self::channel(DEFAULT_CAPTURE_QUEUE_CAPACITY, DEFAULT_CAPTURE_BODY_LIMIT)
            .expect("default gateway capture configuration is valid")
    }

    pub(crate) const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub(crate) fn emit(&self, event: GatewayCaptureEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {
                self.metrics
                    .inner
                    .emitted_events
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics
                    .inner
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.metrics
                    .inner
                    .dropped_receiver_closed
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn mark_payload(&self, payload: &CapturedPayload) {
        if payload.truncated {
            self.metrics
                .inner
                .truncated_bodies
                .fetch_add(1, Ordering::Relaxed);
        }
        if !payload.complete {
            self.metrics
                .inner
                .incomplete_streams
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CaptureMetrics {
    inner: Arc<CaptureMetricCounters>,
}

impl CaptureMetrics {
    #[must_use]
    pub fn snapshot(&self) -> CaptureMetricSnapshot {
        CaptureMetricSnapshot {
            emitted_events: self.inner.emitted_events.load(Ordering::Relaxed),
            dropped_queue_full: self.inner.dropped_queue_full.load(Ordering::Relaxed),
            dropped_receiver_closed: self.inner.dropped_receiver_closed.load(Ordering::Relaxed),
            truncated_bodies: self.inner.truncated_bodies.load(Ordering::Relaxed),
            incomplete_streams: self.inner.incomplete_streams.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default)]
struct CaptureMetricCounters {
    emitted_events: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_receiver_closed: AtomicU64,
    truncated_bodies: AtomicU64,
    incomplete_streams: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureMetricSnapshot {
    pub emitted_events: u64,
    pub dropped_queue_full: u64,
    pub dropped_receiver_closed: u64,
    pub truncated_bodies: u64,
    pub incomplete_streams: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayCaptureEvent {
    Request(GatewayRequestCapture),
    Response(GatewayResponseCapture),
    UpstreamFailure(GatewayUpstreamFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRequestCapture {
    pub capture_id: String,
    pub observed_at_unix_ms: u64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub client_addr: Option<SocketAddr>,
    pub process_id: Option<u32>,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: CapturedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayResponseCapture {
    pub capture_id: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub duration_ms: u64,
    pub body: CapturedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayUpstreamFailure {
    pub capture_id: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPayload {
    pub bytes: Bytes,
    pub truncated: bool,
    pub complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureConfigError {
    ZeroQueueCapacity,
    ZeroBodyLimit,
}

impl fmt::Display for CaptureConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroQueueCapacity => write!(formatter, "capture queue capacity must be positive"),
            Self::ZeroBodyLimit => write!(formatter, "capture body limit must be positive"),
        }
    }
}

impl std::error::Error for CaptureConfigError {}

pub(crate) struct PayloadAccumulator {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
    observed_bytes: u64,
}

impl PayloadAccumulator {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(64 * 1024)),
            limit,
            truncated: false,
            observed_bytes: 0,
        }
    }

    pub(crate) fn push(&mut self, chunk: &Bytes) {
        self.observed_bytes = self
            .observed_bytes
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if chunk.len() <= remaining {
            self.bytes.extend_from_slice(chunk);
        } else {
            self.bytes.extend_from_slice(&chunk[..remaining]);
            self.truncated = true;
        }
    }

    fn finish(&mut self, complete: bool) -> CapturedPayload {
        CapturedPayload {
            bytes: Bytes::from(std::mem::take(&mut self.bytes)),
            truncated: self.truncated,
            complete,
        }
    }

    fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }
}

pub(crate) struct RequestCaptureGuard {
    capture: GatewayCapture,
    metadata: Option<RequestMetadata>,
    payload: PayloadAccumulator,
    expected_body_bytes: Option<u64>,
}

impl RequestCaptureGuard {
    pub(crate) fn new(
        capture: GatewayCapture,
        metadata: RequestMetadata,
        expected_body_bytes: Option<u64>,
    ) -> Self {
        let limit = capture.max_body_bytes();
        Self {
            capture,
            metadata: Some(metadata),
            payload: PayloadAccumulator::new(limit),
            expected_body_bytes,
        }
    }

    pub(crate) fn push(&mut self, chunk: &Bytes) {
        self.payload.push(chunk);
    }

    pub(crate) fn complete(&mut self) {
        self.finish(true);
    }

    fn finish(&mut self, complete: bool) {
        let Some(metadata) = self.metadata.take() else {
            return;
        };
        let complete = complete
            || self
                .expected_body_bytes
                .is_some_and(|expected| self.payload.observed_bytes() >= expected);
        let payload = self.payload.finish(complete);
        self.capture.mark_payload(&payload);
        self.capture
            .emit(GatewayCaptureEvent::Request(GatewayRequestCapture {
                capture_id: metadata.capture_id,
                observed_at_unix_ms: metadata.observed_at_unix_ms,
                method: metadata.method,
                scheme: metadata.scheme,
                host: metadata.host,
                port: metadata.port,
                path: metadata.path,
                client_addr: metadata.client_addr,
                process_id: metadata.process_id,
                query: metadata.query,
                headers: metadata.headers,
                body: payload,
            }));
    }
}

impl Drop for RequestCaptureGuard {
    fn drop(&mut self) {
        self.finish(false);
    }
}

pub(crate) struct ResponseCaptureGuard {
    capture: GatewayCapture,
    metadata: Option<ResponseMetadata>,
    payload: PayloadAccumulator,
    expected_body_bytes: Option<u64>,
}

impl ResponseCaptureGuard {
    pub(crate) fn new(
        capture: GatewayCapture,
        metadata: ResponseMetadata,
        expected_body_bytes: Option<u64>,
    ) -> Self {
        let limit = capture.max_body_bytes();
        Self {
            capture,
            metadata: Some(metadata),
            payload: PayloadAccumulator::new(limit),
            expected_body_bytes,
        }
    }

    pub(crate) fn push(&mut self, chunk: &Bytes) {
        self.payload.push(chunk);
    }

    pub(crate) fn complete(&mut self) {
        self.finish(true);
    }

    fn finish(&mut self, complete: bool) {
        let Some(metadata) = self.metadata.take() else {
            return;
        };
        let complete = complete
            || self
                .expected_body_bytes
                .is_some_and(|expected| self.payload.observed_bytes() >= expected);
        let payload = self.payload.finish(complete);
        self.capture.mark_payload(&payload);
        self.capture
            .emit(GatewayCaptureEvent::Response(GatewayResponseCapture {
                capture_id: metadata.capture_id,
                status: metadata.status,
                headers: metadata.headers,
                duration_ms: elapsed_ms(metadata.started),
                body: payload,
            }));
    }
}

impl Drop for ResponseCaptureGuard {
    fn drop(&mut self) {
        self.finish(false);
    }
}

pub(crate) struct RequestMetadata {
    pub capture_id: String,
    pub observed_at_unix_ms: u64,
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub client_addr: Option<SocketAddr>,
    pub process_id: Option<u32>,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
}

pub(crate) struct ResponseMetadata {
    pub capture_id: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub started: Instant,
}

pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
