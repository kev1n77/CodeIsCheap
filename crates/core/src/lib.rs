//! Trusted ingestion boundary between capture transports and persistence.

use std::fmt;

use codeischeap_capture_ipc::{IpcError, receive_from_reader, receive_one};
use codeischeap_capture_policy::{CapturePolicy, PolicyError, SanitizedCapture};
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
    policy.sanitize_envelope(envelope).map_err(Into::into)
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
    policy.sanitize_envelope(envelope).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use codeischeap_capture_ipc::{
        CAPTURE_ENVELOPE_VERSION, CaptureEnvelope, CaptureSource, CapturedBody, CapturedBodyState,
        CapturedField, CapturedRequest,
    };
    use codeischeap_capture_policy::PolicyError;
    use tokio::io::{AsyncWriteExt, BufReader};

    use super::*;

    fn envelope(path: &str) -> CaptureEnvelope {
        CaptureEnvelope {
            version: CAPTURE_ENVELOPE_VERSION.to_owned(),
            capture_id: "core_ingest_test".to_owned(),
            observed_at_unix_ms: 1_721_000_000_000,
            source: CaptureSource::Mitmproxy,
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
            "version": "0.1",
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
        let encoded = serde_json::to_string(&sanitized.envelope).expect("result must encode");

        assert_eq!(sanitized.target_id, "openai");
        assert_eq!(sanitized.newly_redacted, 1);
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
}
