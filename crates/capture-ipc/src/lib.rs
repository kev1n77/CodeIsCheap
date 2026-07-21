//! Authenticated, bounded local IPC used by capture sidecars.
//!
//! The sidecar must remove credentials before serializing a [`CaptureEnvelope`].
//! Authentication is transported in a separate first frame so it cannot be
//! confused with data that may later be persisted.

use std::fmt;
use std::future::{Future, ready};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::mem::size_of;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt as _;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::time::timeout;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{GENERIC_ALL, HANDLE, LocalFree};
#[cfg(windows)]
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
#[cfg(windows)]
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub const CAPTURE_ENVELOPE_VERSION: &str = "0.1";
pub const IPC_PROTOCOL: &str = "codeischeap.capture-ipc";
pub const IPC_PROTOCOL_VERSION: &str = "0.6";
pub const IPC_ORIGIN_MITMPROXY: &str = "mitmproxy";
pub const CLIENT_LABEL_HEADER: &str = "x-codeischeap-client";
pub const MAX_AUTH_FRAME_BYTES: usize = 1024;
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_CONNECTION_DEADLINE: Duration = Duration::from_secs(2);
const ACCEPTED_FRAME: &[u8] = b"{\"status\":\"accepted\"}\n";

#[cfg(windows)]
const NAMED_PIPE_PREFIX: &str = r"\\.\pipe\CodeIsCheap-capture-";
#[cfg(windows)]
const MAX_NAMED_PIPE_NAME_CHARS: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureEnvelope {
    pub version: String,
    pub capture_id: String,
    pub observed_at_unix_ms: u64,
    pub source: CaptureSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<CaptureAttribution>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureAttribution {
    pub application: String,
    pub source: AttributionSource,
    pub confidence: AttributionConfidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributionSource {
    ClientLabel,
    UserAgent,
    CaptureMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributionConfidence {
    High,
    Medium,
    Low,
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
    origin: String,
    token: String,
    #[serde(default)]
    transport: Option<CaptureTransport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureTransport {
    pub client_addr: SocketAddr,
    pub server_addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReceivedCapture {
    pub envelope: CaptureEnvelope,
    pub transport: Option<CaptureTransport>,
}

#[derive(Debug)]
pub enum IpcError {
    Io(io::Error),
    NonLoopbackListener,
    NonLoopbackPeer,
    EmptyFrame,
    AuthFrameTooLarge,
    FrameTooLarge,
    ConnectionDeadlineExceeded,
    InvalidAuthFrame(serde_json::Error),
    InvalidEnvelope(serde_json::Error),
    UnsupportedProtocol,
    UnsupportedOrigin,
    Unauthorized,
    UnauthorizedPeer,
    InvalidTransport,
    UnsupportedEnvelopeVersion(String),
}

impl fmt::Display for IpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "capture IPC I/O failed: {error}"),
            Self::NonLoopbackListener => write!(formatter, "capture IPC must listen on loopback"),
            Self::NonLoopbackPeer => write!(formatter, "capture IPC rejected a non-loopback peer"),
            Self::EmptyFrame => write!(formatter, "capture IPC received an empty frame"),
            Self::AuthFrameTooLarge => {
                write!(formatter, "capture IPC auth frame exceeded the size limit")
            }
            Self::FrameTooLarge => write!(formatter, "capture IPC frame exceeded the size limit"),
            Self::ConnectionDeadlineExceeded => {
                write!(formatter, "capture IPC connection deadline was exceeded")
            }
            Self::InvalidAuthFrame(_) => write!(formatter, "capture IPC auth frame is invalid"),
            Self::InvalidEnvelope(_) => write!(formatter, "capture envelope is invalid"),
            Self::UnsupportedProtocol => write!(formatter, "capture IPC protocol is unsupported"),
            Self::UnsupportedOrigin => write!(formatter, "capture IPC origin is unsupported"),
            Self::Unauthorized => write!(formatter, "capture IPC authentication failed"),
            Self::UnauthorizedPeer => {
                write!(formatter, "capture IPC peer process is unauthorized")
            }
            Self::InvalidTransport => {
                write!(formatter, "capture IPC transport context is invalid")
            }
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

#[cfg(windows)]
struct LocalAllocation(*mut core::ffi::c_void);

#[cfg(windows)]
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[cfg(windows)]
struct OwnedSid(Vec<u32>);

#[cfg(windows)]
impl OwnedSid {
    fn copy_from(source: PSID) -> io::Result<Self> {
        let byte_len = unsafe { GetLengthSid(source) };
        if byte_len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut words = vec![
            0u32;
            usize::try_from(byte_len)
                .unwrap()
                .div_ceil(size_of::<u32>())
        ];
        if unsafe {
            windows_sys::Win32::Security::CopySid(byte_len, words.as_mut_ptr().cast(), source)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(words))
    }

    fn current_user() -> io::Result<Self> {
        let mut raw_token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token.cast()) };
        let mut required = 0u32;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle().cast(),
                TokenUser,
                std::ptr::null_mut(),
                0,
                &mut required,
            );
        }
        if required == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![
            0usize;
            usize::try_from(required)
                .unwrap()
                .div_ceil(size_of::<usize>())
        ];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle().cast(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        Self::copy_from(token_user.User.Sid)
    }

    fn local_system() -> io::Result<Self> {
        let mut byte_len = SECURITY_MAX_SID_SIZE;
        let mut words = vec![
            0u32;
            usize::try_from(byte_len)
                .unwrap()
                .div_ceil(size_of::<u32>())
        ];
        if unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                std::ptr::null_mut(),
                words.as_mut_ptr().cast(),
                &mut byte_len,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(words))
    }

    fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }

    fn to_string(&self) -> io::Result<String> {
        let mut raw = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(self.as_psid(), &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allocation = LocalAllocation(raw.cast());
        let mut len = 0usize;
        while unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, len) })
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        drop(allocation);
        Ok(value)
    }
}

#[cfg(windows)]
fn owner_only_security_descriptor() -> io::Result<LocalAllocation> {
    let user_sid = OwnedSid::current_user()?.to_string()?;
    let sddl = format!("O:{user_sid}D:P(A;;GA;;;SY)(A;;GA;;;{user_sid})");
    let encoded = OsStr::new(&sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            encoded.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalAllocation(descriptor))
}

#[cfg(windows)]
fn valid_named_pipe_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(NAMED_PIPE_PREFIX) else {
        return false;
    };
    !suffix.is_empty()
        && name.encode_utf16().count() <= MAX_NAMED_PIPE_NAME_CHARS
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(windows)]
pub struct OwnerOnlyNamedPipeListener {
    name: String,
    pending: NamedPipeServer,
}

#[cfg(windows)]
impl OwnerOnlyNamedPipeListener {
    pub fn bind(name: impl Into<String>) -> io::Result<Self> {
        let name = name.into();
        let pending = create_owner_only_named_pipe_instance(&name, true)?;
        Ok(Self { name, pending })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn pending_server(&self) -> &NamedPipeServer {
        &self.pending
    }
}

#[cfg(windows)]
fn create_owner_only_named_pipe_instance(
    name: &str,
    first_instance: bool,
) -> io::Result<NamedPipeServer> {
    if !valid_named_pipe_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "capture IPC named pipe has an invalid local name",
        ));
    }
    let descriptor = owner_only_security_descriptor()?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true)
        .max_instances(2);
    let server = unsafe {
        options
            .create_with_security_attributes_raw(name, std::ptr::from_mut(&mut attributes).cast())?
    };
    if !named_pipe_is_owner_only(&server)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "capture IPC named pipe DACL is not owner-only",
        ));
    }
    Ok(server)
}

#[cfg(windows)]
pub fn named_pipe_is_owner_only(server: &NamedPipeServer) -> io::Result<bool> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            server.as_raw_handle().cast(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Ok(false);
    }
    let current_user = OwnedSid::current_user()?;
    let local_system = OwnedSid::local_system()?;
    if unsafe { EqualSid(owner, current_user.as_psid()) } == 0 {
        return Ok(false);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 || unsafe { (*dacl).AceCount } != 2 {
        return Ok(false);
    }

    let mut user_allowed = false;
    let mut system_allowed = false;
    for index in 0..2 {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || ace.Header.AceFlags & INHERITED_ACE as u8 != 0
            || !matches!(ace.Mask, GENERIC_ALL | FILE_ALL_ACCESS)
        {
            return Ok(false);
        }
        let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        if unsafe { EqualSid(sid, current_user.as_psid()) } != 0 {
            user_allowed = true;
        } else if unsafe { EqualSid(sid, local_system.as_psid()) } != 0 {
            system_allowed = true;
        } else {
            return Ok(false);
        }
    }
    Ok(user_allowed && system_allowed)
}

#[cfg(windows)]
pub fn named_pipe_client_process_id(server: &NamedPipeServer) -> io::Result<u32> {
    let mut process_id = 0u32;
    if unsafe { GetNamedPipeClientProcessId(server.as_raw_handle().cast(), &mut process_id) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(process_id)
}

pub async fn receive_one(
    listener: &TcpListener,
    expected_token: &str,
) -> Result<CaptureEnvelope, IpcError> {
    Ok(receive_one_with_transport(listener, expected_token)
        .await?
        .envelope)
}

pub async fn receive_one_with_transport(
    listener: &TcpListener,
    expected_token: &str,
) -> Result<ReceivedCapture, IpcError> {
    receive_one_with_transport_deadline(listener, expected_token, DEFAULT_CONNECTION_DEADLINE).await
}

pub async fn receive_one_with_transport_verified<F, Fut>(
    listener: &TcpListener,
    expected_token: &str,
    verify_peer: F,
) -> Result<ReceivedCapture, IpcError>
where
    F: FnOnce(SocketAddr, SocketAddr) -> Fut,
    Fut: Future<Output = bool>,
{
    receive_one_with_transport_verifier_deadline(
        listener,
        expected_token,
        DEFAULT_CONNECTION_DEADLINE,
        verify_peer,
    )
    .await
}

pub async fn receive_one_with_deadline(
    listener: &TcpListener,
    expected_token: &str,
    connection_deadline: Duration,
) -> Result<CaptureEnvelope, IpcError> {
    Ok(
        receive_one_with_transport_deadline(listener, expected_token, connection_deadline)
            .await?
            .envelope,
    )
}

pub async fn receive_one_with_transport_deadline(
    listener: &TcpListener,
    expected_token: &str,
    connection_deadline: Duration,
) -> Result<ReceivedCapture, IpcError> {
    receive_one_with_transport_verifier_deadline(
        listener,
        expected_token,
        connection_deadline,
        |_, _| ready(true),
    )
    .await
}

async fn receive_one_with_transport_verifier_deadline<F, Fut>(
    listener: &TcpListener,
    expected_token: &str,
    connection_deadline: Duration,
    verify_peer: F,
) -> Result<ReceivedCapture, IpcError>
where
    F: FnOnce(SocketAddr, SocketAddr) -> Fut,
    Fut: Future<Output = bool>,
{
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(IpcError::NonLoopbackListener);
    }

    let (stream, peer) = listener.accept().await?;
    if !peer.ip().is_loopback() {
        return Err(IpcError::NonLoopbackPeer);
    }
    let server = stream.local_addr()?;

    timeout(connection_deadline, async move {
        if !verify_peer(peer, server).await {
            return Err(IpcError::UnauthorizedPeer);
        }
        receive_from_stream(stream, expected_token).await
    })
    .await
    .map_err(|_| IpcError::ConnectionDeadlineExceeded)?
}

#[cfg(windows)]
pub async fn receive_one_named_pipe_with_transport_verified<F>(
    listener: &mut OwnerOnlyNamedPipeListener,
    expected_token: &str,
    verify_peer: F,
) -> Result<ReceivedCapture, IpcError>
where
    F: FnOnce(&NamedPipeServer) -> bool,
{
    receive_one_named_pipe_with_transport_verifier_deadline(
        listener,
        expected_token,
        DEFAULT_CONNECTION_DEADLINE,
        verify_peer,
    )
    .await
}

#[cfg(windows)]
pub async fn receive_one_named_pipe_with_transport_deadline(
    listener: &mut OwnerOnlyNamedPipeListener,
    expected_token: &str,
    connection_deadline: Duration,
) -> Result<ReceivedCapture, IpcError> {
    receive_one_named_pipe_with_transport_verifier_deadline(
        listener,
        expected_token,
        connection_deadline,
        |_| true,
    )
    .await
}

#[cfg(windows)]
async fn receive_one_named_pipe_with_transport_verifier_deadline<F>(
    listener: &mut OwnerOnlyNamedPipeListener,
    expected_token: &str,
    connection_deadline: Duration,
    verify_peer: F,
) -> Result<ReceivedCapture, IpcError>
where
    F: FnOnce(&NamedPipeServer) -> bool,
{
    listener.pending.connect().await?;
    let replacement = match create_owner_only_named_pipe_instance(&listener.name, false) {
        Ok(replacement) => replacement,
        Err(error) => {
            let _ = listener.pending.disconnect();
            return Err(IpcError::Io(error));
        }
    };
    let mut connected = std::mem::replace(&mut listener.pending, replacement);
    let received = timeout(connection_deadline, async {
        if !verify_peer(&connected) {
            return Err(IpcError::UnauthorizedPeer);
        }
        receive_from_stream(&mut connected, expected_token).await
    })
    .await
    .unwrap_or(Err(IpcError::ConnectionDeadlineExceeded));
    drop(connected);
    received
}

#[cfg(unix)]
pub async fn receive_one_unix_with_transport(
    listener: &UnixListener,
    expected_token: &str,
) -> Result<ReceivedCapture, IpcError> {
    receive_one_unix_with_transport_verifier_deadline(
        listener,
        expected_token,
        DEFAULT_CONNECTION_DEADLINE,
        |_, _| true,
    )
    .await
}

#[cfg(unix)]
pub async fn receive_one_unix_with_transport_verified<F>(
    listener: &UnixListener,
    expected_token: &str,
    verify_peer: F,
) -> Result<ReceivedCapture, IpcError>
where
    F: FnOnce(u32, Option<i32>) -> bool,
{
    receive_one_unix_with_transport_verifier_deadline(
        listener,
        expected_token,
        DEFAULT_CONNECTION_DEADLINE,
        verify_peer,
    )
    .await
}

#[cfg(unix)]
pub async fn receive_one_unix_with_transport_deadline(
    listener: &UnixListener,
    expected_token: &str,
    connection_deadline: Duration,
) -> Result<ReceivedCapture, IpcError> {
    receive_one_unix_with_transport_verifier_deadline(
        listener,
        expected_token,
        connection_deadline,
        |_, _| true,
    )
    .await
}

#[cfg(unix)]
async fn receive_one_unix_with_transport_verifier_deadline<F>(
    listener: &UnixListener,
    expected_token: &str,
    connection_deadline: Duration,
    verify_peer: F,
) -> Result<ReceivedCapture, IpcError>
where
    F: FnOnce(u32, Option<i32>) -> bool,
{
    let (stream, _) = listener.accept().await?;
    let credentials = stream.peer_cred()?;
    timeout(connection_deadline, async move {
        if !verify_peer(credentials.uid(), credentials.pid()) {
            return Err(IpcError::UnauthorizedPeer);
        }
        receive_from_stream(stream, expected_token).await
    })
    .await
    .map_err(|_| IpcError::ConnectionDeadlineExceeded)?
}

async fn receive_from_stream<S>(
    stream: S,
    expected_token: &str,
) -> Result<ReceivedCapture, IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let capture = receive_from_reader_with_transport(&mut reader, expected_token).await?;
    reader.get_mut().write_all(ACCEPTED_FRAME).await?;
    Ok(capture)
}

pub async fn receive_from_reader<R>(
    reader: &mut R,
    expected_token: &str,
) -> Result<CaptureEnvelope, IpcError>
where
    R: AsyncBufRead + Unpin,
{
    Ok(receive_from_reader_with_transport(reader, expected_token)
        .await?
        .envelope)
}

pub async fn receive_from_reader_with_transport<R>(
    reader: &mut R,
    expected_token: &str,
) -> Result<ReceivedCapture, IpcError>
where
    R: AsyncBufRead + Unpin,
{
    let auth_bytes =
        read_frame(reader, MAX_AUTH_FRAME_BYTES)
            .await
            .map_err(|error| match error {
                IpcError::FrameTooLarge => IpcError::AuthFrameTooLarge,
                error => error,
            })?;
    let auth: AuthFrame =
        serde_json::from_slice(&auth_bytes).map_err(IpcError::InvalidAuthFrame)?;
    if auth.protocol != IPC_PROTOCOL || auth.version != IPC_PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedProtocol);
    }
    if auth.origin != IPC_ORIGIN_MITMPROXY {
        return Err(IpcError::UnsupportedOrigin);
    }
    if expected_token.is_empty()
        || !bool::from(auth.token.as_bytes().ct_eq(expected_token.as_bytes()))
    {
        return Err(IpcError::Unauthorized);
    }
    if auth.transport.is_some_and(|transport| {
        !transport.client_addr.ip().is_loopback()
            || !transport.server_addr.ip().is_loopback()
            || transport.client_addr.is_ipv4() != transport.server_addr.is_ipv4()
    }) {
        return Err(IpcError::InvalidTransport);
    }

    let envelope_bytes = read_frame(reader, MAX_FRAME_BYTES).await?;
    let envelope: CaptureEnvelope =
        serde_json::from_slice(&envelope_bytes).map_err(IpcError::InvalidEnvelope)?;
    if envelope.version != CAPTURE_ENVELOPE_VERSION {
        return Err(IpcError::UnsupportedEnvelopeVersion(envelope.version));
    }
    Ok(ReceivedCapture {
        envelope,
        transport: auth.transport,
    })
}

async fn read_frame<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, IpcError>
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
        if frame.len().saturating_add(content.len()) > max_bytes {
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
