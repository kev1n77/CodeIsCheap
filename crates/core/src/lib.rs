//! Trusted ingestion boundary between capture transports and persistence.

use std::fmt;

use codeischeap_adapters::{AdapterRegistry, ParseIssue};
use codeischeap_capture_ipc::{
    CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureOutcome, CaptureSource, CapturedBody,
    CapturedBodyState, CapturedField, CapturedRequest, CapturedResponse, CapturedUpstreamFailure,
    IpcError, ResponseCompleteness, receive_from_reader, receive_one,
};
use codeischeap_capture_policy::{CapturePolicy, PolicyError, SanitizedCapture};
use codeischeap_gateway::{
    CapturedPayload, GatewayCaptureEvent, GatewayRequestCapture, GatewayResponseCapture,
    GatewayUpstreamFailure,
};
use codeischeap_prompt_ir::PromptIr;
use codeischeap_storage::{EncryptedStore, StorageError};
use tokio::io::AsyncBufRead;
use tokio::net::TcpListener;

#[derive(Debug)]
pub enum IngestError {
    Ipc(IpcError),
    Policy(PolicyError),
}

impl fmt::Display for IngestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipc(error) => write!(formatter, "capture ingestion rejected IPC input: {error}"),
            Self::Policy(error) => {
                write!(
                    formatter,
                    "capture ingestion rejected policy input: {error}"
                )
            }
        }
    }
}

impl std::error::Error for IngestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ipc(error) => Some(error),
            Self::Policy(error) => Some(error),
        }
    }
}

impl From<IpcError> for IngestError {
    fn from(error: IpcError) -> Self {
        Self::Ipc(error)
    }
}

impl From<PolicyError> for IngestError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

pub async fn ingest_one(
    listener: &TcpListener,
    expected_token: &str,
    policy: &CapturePolicy,
) -> Result<SanitizedCapture, IngestError> {
    let envelope = receive_one(listener, expected_token).await?;
    ingest_envelope(envelope, policy)
}

pub async fn ingest_from_reader<R>(
    reader: &mut R,
    expected_token: &str,
    policy: &CapturePolicy,
) -> Result<SanitizedCapture, IngestError>
where
    R: AsyncBufRead + Unpin,
{
    let envelope = receive_from_reader(reader, expected_token).await?;
    ingest_envelope(envelope, policy)
}

pub fn ingest_envelope(
    envelope: CaptureEnvelope,
    policy: &CapturePolicy,
) -> Result<SanitizedCapture, IngestError> {
    policy.sanitize_envelope(envelope).map_err(Into::into)
}

pub fn persist_capture(
    store: &mut EncryptedStore,
    capture: &SanitizedCapture,
    prompt_ir: Option<&PromptIr>,
) -> Result<(), StorageError> {
    store.upsert_capture(capture, prompt_ir)
}

#[derive(Debug)]
pub enum GatewayCaptureError {
    Policy(PolicyError),
    Storage(StorageError),
}

impl fmt::Display for GatewayCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(error) => write!(formatter, "gateway capture was rejected: {error}"),
            Self::Storage(error) => write!(formatter, "gateway capture could not persist: {error}"),
        }
    }
}

impl std::error::Error for GatewayCaptureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Storage(error) => Some(error),
        }
    }
}

impl From<PolicyError> for GatewayCaptureError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<StorageError> for GatewayCaptureError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum GatewayCaptureOutcome {
    Persisted(PersistedGatewayCapture),
    ResponseObserved(ObservedGatewayResponse),
    UpstreamFailed(ObservedGatewayFailure),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PersistedGatewayCapture {
    pub capture_id: String,
    pub adapter_id: Option<String>,
    pub issues: Vec<ParseIssue>,
    pub raw_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedGatewayResponse {
    pub capture_id: String,
    pub status: u16,
    pub duration_ms: u64,
    pub complete: bool,
    pub truncated: bool,
    pub persisted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedGatewayFailure {
    pub capture_id: String,
    pub duration_ms: u64,
    pub persisted: bool,
}

pub fn process_gateway_event(
    store: &mut EncryptedStore,
    policy: &CapturePolicy,
    adapters: &AdapterRegistry,
    event: GatewayCaptureEvent,
) -> Result<GatewayCaptureOutcome, GatewayCaptureError> {
    match event {
        GatewayCaptureEvent::Request(request) => {
            let sanitized = policy.sanitize_envelope(request_envelope(request, policy))?;
            let parsed = adapters.parse(&sanitized);
            persist_capture(store, &sanitized, parsed.prompt_ir.as_ref())?;
            Ok(GatewayCaptureOutcome::Persisted(PersistedGatewayCapture {
                capture_id: sanitized.envelope().capture_id.clone(),
                adapter_id: parsed.adapter_id,
                issues: parsed.issues,
                raw_fallback: parsed.raw_fallback,
            }))
        }
        GatewayCaptureEvent::Response(response) => {
            let observed = response_outcome(store, policy, adapters, response)?;
            Ok(GatewayCaptureOutcome::ResponseObserved(observed))
        }
        GatewayCaptureEvent::UpstreamFailure(failure) => {
            let observed = failure_outcome(store, policy, adapters, failure)?;
            Ok(GatewayCaptureOutcome::UpstreamFailed(observed))
        }
    }
}

fn request_envelope(request: GatewayRequestCapture, policy: &CapturePolicy) -> CaptureEnvelope {
    let GatewayRequestCapture {
        capture_id,
        observed_at_unix_ms,
        method,
        scheme,
        host,
        port,
        path,
        client_addr: _,
        process_id,
        query,
        headers,
        body,
    } = request;
    let content_type = content_type(&headers).map(str::to_owned);
    let captured_headers = captured_fields(headers);
    let attribution = process_id
        .filter(|process_id| *process_id != 0)
        .map(|process_id| {
            let mut attribution = policy.attribution_for(CaptureSource::Gateway, &captured_headers);
            attribution.process_id = Some(process_id);
            attribution
        });
    CaptureEnvelope {
        version: CAPTURE_ENVELOPE_VERSION.to_owned(),
        capture_id,
        observed_at_unix_ms,
        source: CaptureSource::Gateway,
        attribution,
        request: CapturedRequest {
            method,
            scheme,
            host,
            port,
            path,
            query: captured_fields(query),
            headers: captured_headers,
            body: captured_body(&body, content_type.as_deref(), false),
        },
        outcome: None,
        redactions: Vec::new(),
    }
}

fn captured_fields(fields: Vec<(String, String)>) -> Vec<CapturedField> {
    fields
        .into_iter()
        .map(|(name, value)| CapturedField { name, value })
        .collect()
}

fn captured_body(
    payload: &CapturedPayload,
    content_type: Option<&str>,
    allow_text: bool,
) -> CapturedBody {
    if payload.bytes.is_empty() {
        return CapturedBody {
            state: CapturedBodyState::Empty,
            content: None,
        };
    }
    if payload.truncated || !payload.complete {
        return CapturedBody {
            state: CapturedBodyState::Truncated,
            content: None,
        };
    }
    let Some(content_type) = content_type else {
        return CapturedBody {
            state: CapturedBodyState::OmittedUnsupportedContentType,
            content: None,
        };
    };
    let Ok(text) = std::str::from_utf8(&payload.bytes) else {
        return CapturedBody {
            state: CapturedBodyState::InvalidUtf8,
            content: None,
        };
    };
    if allow_text && is_text_content_type(content_type) {
        return CapturedBody {
            state: CapturedBodyState::Text,
            content: Some(serde_json::Value::String(text.to_owned())),
        };
    }
    if !is_json_content_type(content_type) {
        return CapturedBody {
            state: CapturedBodyState::OmittedUnsupportedContentType,
            content: None,
        };
    }
    match serde_json::from_slice(&payload.bytes) {
        Ok(content) => CapturedBody {
            state: CapturedBodyState::Json,
            content: Some(content),
        },
        Err(_) => CapturedBody {
            state: CapturedBodyState::InvalidJson,
            content: None,
        },
    }
}

fn is_text_content_type(content_type: &str) -> bool {
    let media_type = media_type(content_type);
    media_type.starts_with("text/")
        || matches!(
            media_type.as_str(),
            "application/x-ndjson" | "application/json-seq" | "application/ndjson"
        )
}

fn content_type(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str())
}

fn is_json_content_type(content_type: &str) -> bool {
    let media_type = media_type(content_type);
    media_type == "application/json" || media_type.ends_with("+json")
}

fn media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn response_outcome(
    store: &mut EncryptedStore,
    policy: &CapturePolicy,
    adapters: &AdapterRegistry,
    response: GatewayResponseCapture,
) -> Result<ObservedGatewayResponse, GatewayCaptureError> {
    let content_type = content_type(&response.headers).map(str::to_owned);
    let complete = response.body.complete;
    let truncated = response.body.truncated;
    let outcome = CaptureOutcome::Response(CapturedResponse {
        status: response.status,
        headers: captured_fields(response.headers),
        body: captured_body(&response.body, content_type.as_deref(), true),
        duration_ms: response.duration_ms,
        completeness: if truncated {
            ResponseCompleteness::Truncated
        } else if complete {
            ResponseCompleteness::Complete
        } else {
            ResponseCompleteness::Incomplete
        },
    });
    let persisted = persist_outcome(store, policy, adapters, &response.capture_id, outcome)?;
    Ok(ObservedGatewayResponse {
        capture_id: response.capture_id,
        status: response.status,
        duration_ms: response.duration_ms,
        complete,
        truncated,
        persisted,
    })
}

fn failure_outcome(
    store: &mut EncryptedStore,
    policy: &CapturePolicy,
    adapters: &AdapterRegistry,
    failure: GatewayUpstreamFailure,
) -> Result<ObservedGatewayFailure, GatewayCaptureError> {
    let outcome = CaptureOutcome::UpstreamFailure(CapturedUpstreamFailure {
        duration_ms: failure.duration_ms,
    });
    let persisted = persist_outcome(store, policy, adapters, &failure.capture_id, outcome)?;
    Ok(ObservedGatewayFailure {
        capture_id: failure.capture_id,
        duration_ms: failure.duration_ms,
        persisted,
    })
}

fn persist_outcome(
    store: &mut EncryptedStore,
    policy: &CapturePolicy,
    adapters: &AdapterRegistry,
    capture_id: &str,
    outcome: CaptureOutcome,
) -> Result<bool, GatewayCaptureError> {
    let Some(stored) = store.get_capture(capture_id)? else {
        return Ok(false);
    };
    let mut envelope = stored.envelope;
    envelope.outcome = Some(outcome);
    let sanitized = policy.sanitize_envelope(envelope)?;
    let parsed = adapters.parse(&sanitized);
    let prompt_ir = parsed.prompt_ir.as_ref().or(stored.prompt_ir.as_ref());
    store.upsert_capture(&sanitized, prompt_ir)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use codeischeap_capture_ipc::{
        CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureSource, CapturedBody, CapturedBodyState,
        CapturedField, CapturedRequest, IPC_PROTOCOL_VERSION,
    };
    use codeischeap_capture_policy::PolicyError;
    use codeischeap_storage::DatabaseKey;
    use tempfile::tempdir;
    use tokio::io::{AsyncWriteExt, BufReader};

    use super::*;

    fn envelope(path: &str) -> CaptureEnvelope {
        CaptureEnvelope {
            version: CAPTURE_ENVELOPE_VERSION.to_owned(),
            capture_id: "core_ingest_test".to_owned(),
            observed_at_unix_ms: 1_721_000_000_000,
            source: CaptureSource::Mitmproxy,
            attribution: None,
            request: CapturedRequest {
                method: "POST".to_owned(),
                scheme: "https".to_owned(),
                host: "api.openai.com".to_owned(),
                port: 443,
                path: path.to_owned(),
                query: Vec::new(),
                headers: vec![CapturedField {
                    name: "authorization".to_owned(),
                    value: "Bearer core-canary".to_owned(),
                }],
                body: CapturedBody {
                    state: CapturedBodyState::Json,
                    content: Some(serde_json::json!({"input": "preserved prompt"})),
                },
            },
            outcome: None,
            redactions: Vec::new(),
        }
    }

    async fn framed_reader(
        token: &str,
        envelope: CaptureEnvelope,
    ) -> BufReader<tokio::io::DuplexStream> {
        let (mut writer, reader) = tokio::io::duplex(16 * 1024);
        let auth = serde_json::json!({
            "protocol": "codeischeap.capture-ipc",
            "version": IPC_PROTOCOL_VERSION,
            "origin": "mitmproxy",
            "token": token,
        });
        let mut frames = serde_json::to_vec(&auth).expect("auth must encode");
        frames.push(b'\n');
        frames.extend(serde_json::to_vec(&envelope).expect("envelope must encode"));
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
    async fn authenticated_input_is_rescrubbed_before_persistence() {
        let policy = CapturePolicy::load_default().expect("policy must load");
        let mut reader = framed_reader("synthetic-token", envelope("/v1/responses")).await;

        let sanitized = ingest_from_reader(&mut reader, "synthetic-token", &policy)
            .await
            .expect("valid input must be accepted");
        let encoded = serde_json::to_string(sanitized.envelope()).expect("result must encode");

        assert_eq!(sanitized.target_id(), "openai");
        assert_eq!(sanitized.newly_redacted(), 1);
        assert!(!encoded.contains("core-canary"));
        assert!(encoded.contains("preserved prompt"));
    }

    #[tokio::test]
    async fn authenticated_out_of_scope_input_is_rejected() {
        let policy = CapturePolicy::load_default().expect("policy must load");
        let mut reader = framed_reader("synthetic-token", envelope("/v1/files")).await;

        let error = ingest_from_reader(&mut reader, "synthetic-token", &policy)
            .await
            .expect_err("out-of-scope input must be rejected");

        assert!(matches!(
            error,
            IngestError::Policy(PolicyError::OutOfScope)
        ));
    }

    #[tokio::test]
    async fn sanitized_input_can_enter_the_encrypted_store() {
        let policy = CapturePolicy::load_default().expect("policy must load");
        let mut reader = framed_reader("synthetic-token", envelope("/v1/responses")).await;
        let sanitized = ingest_from_reader(&mut reader, "synthetic-token", &policy)
            .await
            .expect("valid input must be accepted");
        let directory = tempdir().expect("temp directory must be created");
        let mut store = EncryptedStore::open(
            directory.path().join("captures.db"),
            DatabaseKey::from_bytes([0x33; 32]),
        )
        .expect("encrypted store must open");

        persist_capture(&mut store, &sanitized, None).expect("capture must persist");

        let stored = store
            .get_capture("core_ingest_test")
            .expect("capture query must succeed")
            .expect("capture must exist");
        let encoded = serde_json::to_string(&stored.envelope).expect("capture must encode");
        assert!(!encoded.contains("core-canary"));
        assert!(encoded.contains("preserved prompt"));
    }
}
