//! Authenticated, bounded local IPC used by capture sidecars.
//!
//! The sidecar must remove credentials before serializing a [`CaptureEnvelope`].
//! Authentication is transported in a separate first frame so it cannot be
//! confused with data that may later be persisted.

use std::fmt;
use std::io;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;

pub const CAPTURE_ENVELOPE_VERSION: &str = "0.1";
pub const IPC_PROTOCOL: &str = "codeischeap.capture-ipc";
pub const IPC_PROTOCOL_VERSION: &str = "0.1";
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureEnvelope {
    pub version: String,
    pub capture_id: String,
    pub observed_at_unix_ms: u64,
    pub source: CaptureSource,
    pub request: CapturedRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<CaptureOutcome>,
    #[serde(default)]
    pub redactions: Vec<CaptureRedaction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSource {
    Gateway,
    Mitmproxy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapturedRequest {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    #[serde(default)]
    pub query: Vec<CapturedField>,
    #[serde(default)]
    pub headers: Vec<CapturedField>,
    pub body: CapturedBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapturedField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapturedBody {
    pub state: CapturedBodyState,
    pub content: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapturedBodyState {
    Empty,
    Json,
    Text,
    InvalidJson,
    InvalidUtf8,
    Truncated,
    OmittedUnsupportedContentType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "result", rename_all = "snake_case")]
pub enum CaptureOutcome {
    Response(CapturedResponse),
    UpstreamFailure(CapturedUpstreamFailure),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapturedResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<CapturedField>,
    pub body: CapturedBody,
    pub duration_ms: u64,
    pub completeness: ResponseCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapturedUpstreamFailure {
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseCompleteness {
    Complete,
    Truncated,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureRedaction {
    pub location: RedactionLocation,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RedactionLocation {
    Header,
    Query,
    Body,
    ResponseHeader,
    ResponseBody,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthFrame {
    protocol: String,
    version: String,
    token: String,
}

#[derive(Debug)]
pub enum IpcError {
    Io(io::Error),
    NonLoopbackListener,
    NonLoopbackPeer,
    EmptyFrame,
    FrameTooLarge,
    InvalidAuthFrame(serde_json::Error),
    InvalidEnvelope(serde_json::Error),
    UnsupportedProtocol,
    Unauthorized,
    UnsupportedEnvelopeVersion(String),
}

impl fmt::Display for IpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "capture IPC I/O failed: {error}"),
            Self::NonLoopbackListener => write!(formatter, "capture IPC must listen on loopback"),
            Self::NonLoopbackPeer => write!(formatter, "capture IPC rejected a non-loopback peer"),
            Self::EmptyFrame => write!(formatter, "capture IPC received an empty frame"),
            Self::FrameTooLarge => write!(formatter, "capture IPC frame exceeded the size limit"),
            Self::InvalidAuthFrame(_) => write!(formatter, "capture IPC auth frame is invalid"),
            Self::InvalidEnvelope(_) => write!(formatter, "capture envelope is invalid"),
            Self::UnsupportedProtocol => write!(formatter, "capture IPC protocol is unsupported"),
            Self::Unauthorized => write!(formatter, "capture IPC authentication failed"),
            Self::UnsupportedEnvelopeVersion(version) => {
                write!(
                    formatter,
                    "capture envelope version {version} is unsupported"
                )
            }
        }
    }
}

impl std::error::Error for IpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidAuthFrame(error) | Self::InvalidEnvelope(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for IpcError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub async fn receive_one(
    listener: &TcpListener,
    expected_token: &str,
) -> Result<CaptureEnvelope, IpcError> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(IpcError::NonLoopbackListener);
    }

    let (stream, peer) = listener.accept().await?;
    if !peer.ip().is_loopback() {
        return Err(IpcError::NonLoopbackPeer);
    }

    receive_from_reader(&mut BufReader::new(stream), expected_token).await
}

pub async fn receive_from_reader<R>(
    reader: &mut R,
    expected_token: &str,
) -> Result<CaptureEnvelope, IpcError>
where
    R: AsyncBufRead + Unpin,
{
    let auth_bytes = read_frame(reader).await?;
    let auth: AuthFrame =
        serde_json::from_slice(&auth_bytes).map_err(IpcError::InvalidAuthFrame)?;
    if auth.protocol != IPC_PROTOCOL || auth.version != IPC_PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedProtocol);
    }
    if expected_token.is_empty() || auth.token != expected_token {
        return Err(IpcError::Unauthorized);
    }

    let envelope_bytes = read_frame(reader).await?;
    let envelope: CaptureEnvelope =
        serde_json::from_slice(&envelope_bytes).map_err(IpcError::InvalidEnvelope)?;
    if envelope.version != CAPTURE_ENVELOPE_VERSION {
        return Err(IpcError::UnsupportedEnvelopeVersion(envelope.version));
    }
    Ok(envelope)
}

async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>, IpcError>
where
    R: AsyncBufRead + Unpin,
{
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(IpcError::EmptyFrame);
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        let content = newline.map_or(available, |position| &available[..position]);
        if frame.len() + content.len() > MAX_FRAME_BYTES {
            return Err(IpcError::FrameTooLarge);
        }
        frame.extend_from_slice(content);
        reader.consume(consumed);

        if newline.is_some() {
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            if frame.is_empty() {
                return Err(IpcError::EmptyFrame);
            }
            return Ok(frame);
        }
    }
}
