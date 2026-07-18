use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    MACOS_PRIVILEGED_HELPER_PROTOCOL_VERSION, MACOS_PROXY_RECOVERY_JOURNAL_FILENAME,
    MacOsProxyBackend, ProxyBackend, ProxySession, ProxySettings, RecoveryError,
    owner_process_is_running, write_json_atomic,
};

const MAX_CONTROL_FRAME_BYTES: usize = 1024;
const HELPER_STATUS_PREFIX: &str = ".codeischeap-proxy-helper-";
const HELPER_STATUS_SUFFIX: &str = ".status";
const HELPER_SOCKET_PREFIX: &str = "codeischeap-proxy-helper-";
const HELPER_SOCKET_SUFFIX: &str = ".sock";

#[derive(Debug, Serialize, Deserialize)]
struct HelperStatus {
    version: String,
    state: HelperStatusState,
    detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HelperStatusState {
    Ready,
    Error,
}

#[derive(Debug, Serialize, Deserialize)]
struct ControlFrame {
    version: String,
    command: ControlCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlCommand {
    Attach,
    Restore,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResponseFrame {
    version: String,
    state: ResponseState,
    detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResponseState {
    Attached,
    Restored,
    Error,
}

pub struct MacOsPrivilegedProxySession {
    stream: UnixStream,
    restored: bool,
}

impl MacOsPrivilegedProxySession {
    pub fn connect(
        status_path: impl AsRef<Path>,
        socket_path: impl AsRef<Path>,
        expected_helper_uid: u32,
        timeout: Duration,
    ) -> Result<Self, RecoveryError> {
        let status_path = status_path.as_ref();
        let socket_path = socket_path.as_ref();
        wait_for_ready_status(status_path, timeout)?;
        validate_socket_owner(socket_path, expected_helper_uid)?;

        let deadline = Instant::now() + timeout;
        let mut stream = loop {
            match UnixStream::connect(socket_path) {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                    ) && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(RecoveryError::Io(error)),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let (peer_uid, _) = peer_identity(&stream)?;
        if peer_uid != expected_helper_uid {
            return Err(RecoveryError::PrivilegedHelper(
                "control socket peer UID does not match the helper".to_owned(),
            ));
        }
        write_frame(
            &mut stream,
            &ControlFrame {
                version: MACOS_PRIVILEGED_HELPER_PROTOCOL_VERSION.to_owned(),
                command: ControlCommand::Attach,
            },
        )?;
        let response: ResponseFrame = read_required_frame(&mut stream)?;
        validate_response(response, ResponseState::Attached)?;
        stream.set_read_timeout(None)?;
        let _ = fs::remove_file(status_path);
        Ok(Self {
            stream,
            restored: false,
        })
    }

    pub fn restore(mut self) -> Result<(), RecoveryError> {
        write_frame(
            &mut self.stream,
            &ControlFrame {
                version: MACOS_PRIVILEGED_HELPER_PROTOCOL_VERSION.to_owned(),
                command: ControlCommand::Restore,
            },
        )?;
        self.stream
            .set_read_timeout(Some(Duration::from_secs(15)))?;
        let response: ResponseFrame = read_required_frame(&mut self.stream)?;
        validate_response(response, ResponseState::Restored)?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for MacOsPrivilegedProxySession {
    fn drop(&mut self) {
        if !self.restored {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
    }
}

pub fn run_macos_privileged_proxy_helper(
    journal_path: impl AsRef<Path>,
    status_path: impl AsRef<Path>,
    socket_path: impl AsRef<Path>,
    endpoint: &str,
    owner_pid: u32,
    owner_uid: u32,
) -> Result<(), RecoveryError> {
    let journal_path = journal_path.as_ref();
    let status_path = status_path.as_ref();
    let socket_path = socket_path.as_ref();
    validate_privileged_configuration(
        journal_path,
        status_path,
        socket_path,
        endpoint,
        owner_pid,
        owner_uid,
    )?;
    let watchdog = env::current_exe()?;
    let desired = helper_proxy_settings(endpoint)?;
    let result = run_macos_proxy_helper_session(
        MacOsProxyBackend::system(),
        desired,
        journal_path,
        status_path,
        socket_path,
        owner_pid,
        owner_uid,
        &watchdog,
    );
    if let Err(error) = &result {
        let _ = write_status(
            status_path,
            owner_uid,
            HelperStatusState::Error,
            Some(error.to_string()),
        );
    }
    result
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn run_macos_proxy_helper_session<B: ProxyBackend>(
    backend: B,
    desired: ProxySettings,
    journal_path: impl AsRef<Path>,
    status_path: impl AsRef<Path>,
    socket_path: impl AsRef<Path>,
    owner_pid: u32,
    owner_uid: u32,
    watchdog_executable: impl AsRef<Path>,
) -> Result<(), RecoveryError> {
    let journal_path = journal_path.as_ref();
    let status_path = status_path.as_ref();
    let socket_path = socket_path.as_ref();
    let cleanup = HelperArtifactCleanup::new(status_path, socket_path);
    let listener = UnixListener::bind(socket_path)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    chown_path(socket_path, owner_uid)?;

    let session = ProxySession::begin(backend, desired, journal_path, watchdog_executable)?;
    write_status(status_path, owner_uid, HelperStatusState::Ready, None)?;
    let mut stream = accept_owner(&listener, owner_pid, owner_uid, Duration::from_secs(15))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let attach: ControlFrame = read_required_frame(&mut stream)?;
    validate_command(&attach, ControlCommand::Attach)?;
    write_response(&mut stream, ResponseState::Attached, None)?;
    let _ = fs::remove_file(status_path);
    stream.set_read_timeout(None)?;

    let command: Option<ControlFrame> = read_frame(&mut stream)?;
    match command {
        None => session.restore(),
        Some(command) if validate_command(&command, ControlCommand::Restore).is_ok() => {
            match session.restore() {
                Ok(()) => {
                    write_response(&mut stream, ResponseState::Restored, None)?;
                    drop(cleanup);
                    Ok(())
                }
                Err(error) => {
                    let _ =
                        write_response(&mut stream, ResponseState::Error, Some(error.to_string()));
                    Err(error)
                }
            }
        }
        Some(_) => {
            let restore = session.restore();
            let protocol = RecoveryError::PrivilegedHelper(
                "control socket received an unexpected command".to_owned(),
            );
            match restore {
                Ok(()) => Err(protocol),
                Err(error) => Err(error),
            }
        }
    }
}

fn validate_privileged_configuration(
    journal_path: &Path,
    status_path: &Path,
    socket_path: &Path,
    endpoint: &str,
    owner_pid: u32,
    owner_uid: u32,
) -> Result<(), RecoveryError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(RecoveryError::PrivilegedHelper(
            "helper must run as root".to_owned(),
        ));
    }
    if owner_uid == 0 || owner_pid <= 1 || !owner_process_is_running(owner_pid)? {
        return Err(RecoveryError::PrivilegedHelper(
            "helper owner identity is invalid or no longer running".to_owned(),
        ));
    }
    let journal_parent = private_owner_directory(journal_path, owner_uid)?;
    let status_parent = private_owner_directory(status_path, owner_uid)?;
    if journal_parent != status_parent {
        return Err(RecoveryError::PrivilegedHelper(
            "journal and status files must share the private recovery directory".to_owned(),
        ));
    }
    if journal_path.file_name().and_then(|name| name.to_str())
        != Some(MACOS_PROXY_RECOVERY_JOURNAL_FILENAME)
    {
        return Err(RecoveryError::PrivilegedHelper(
            "recovery journal filename is not allowed".to_owned(),
        ));
    }
    let status_nonce = helper_nonce(status_path, HELPER_STATUS_PREFIX, HELPER_STATUS_SUFFIX)?;
    let socket_nonce = helper_nonce(socket_path, HELPER_SOCKET_PREFIX, HELPER_SOCKET_SUFFIX)?;
    if status_nonce != socket_nonce {
        return Err(RecoveryError::PrivilegedHelper(
            "helper status and socket identities do not match".to_owned(),
        ));
    }
    let socket_parent = socket_path
        .parent()
        .ok_or_else(|| RecoveryError::PrivilegedHelper("socket path has no parent".to_owned()))?;
    if fs::canonicalize(socket_parent)? != fs::canonicalize(env::temp_dir())? {
        return Err(RecoveryError::PrivilegedHelper(
            "helper socket must use the system temporary directory".to_owned(),
        ));
    }
    if journal_path.exists() || status_path.exists() || socket_path.exists() {
        return Err(RecoveryError::PrivilegedHelper(
            "helper artifacts already exist; recovery or cleanup is required".to_owned(),
        ));
    }
    helper_proxy_settings(endpoint)?;
    Ok(())
}

fn private_owner_directory(path: &Path, owner_uid: u32) -> Result<PathBuf, RecoveryError> {
    if !path.is_absolute() {
        return Err(RecoveryError::PrivilegedHelper(
            "helper paths must be absolute".to_owned(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| RecoveryError::PrivilegedHelper("helper path has no parent".to_owned()))?;
    let canonical = fs::canonicalize(parent)?;
    let metadata = fs::metadata(&canonical)?;
    if metadata.uid() != owner_uid || metadata.mode() & 0o077 != 0 {
        return Err(RecoveryError::PrivilegedHelper(
            "recovery directory must be owned by the requesting user and mode 0700".to_owned(),
        ));
    }
    Ok(canonical)
}

fn helper_nonce<'a>(path: &'a Path, prefix: &str, suffix: &str) -> Result<&'a str, RecoveryError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| RecoveryError::PrivilegedHelper("helper filename is invalid".to_owned()))?;
    let nonce = name
        .strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(suffix))
        .filter(|nonce| {
            !nonce.is_empty()
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .ok_or_else(|| {
            RecoveryError::PrivilegedHelper("helper filename is not allowed".to_owned())
        })?;
    Ok(nonce)
}

fn helper_proxy_settings(endpoint: &str) -> Result<ProxySettings, RecoveryError> {
    let url = Url::parse(endpoint)
        .map_err(|_| RecoveryError::InvalidProxyEndpoint(endpoint.to_owned()))?;
    let host = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .filter(std::net::IpAddr::is_loopback);
    if url.scheme() != "http"
        || host.is_none()
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RecoveryError::InvalidProxyEndpoint(endpoint.to_owned()));
    }
    Ok(ProxySettings::Manual {
        http_proxy: endpoint.to_owned(),
        https_proxy: endpoint.to_owned(),
        bypass: vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ],
    })
}

fn accept_owner(
    listener: &UnixListener,
    owner_pid: u32,
    owner_uid: u32,
    timeout: Duration,
) -> Result<UnixStream, RecoveryError> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let (peer_uid, peer_pid) = peer_identity(&stream)?;
                if peer_uid == owner_uid && peer_pid == owner_pid {
                    return Ok(stream);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(RecoveryError::Io(error)),
        }
        if !owner_process_is_running(owner_pid)? {
            return Err(RecoveryError::PrivilegedHelper(
                "helper owner exited before attaching".to_owned(),
            ));
        }
        if Instant::now() >= deadline {
            return Err(RecoveryError::PrivilegedHelper(
                "helper owner did not attach before the deadline".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn peer_identity(stream: &UnixStream) -> Result<(u32, u32), RecoveryError> {
    let descriptor = stream.as_raw_fd();
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(descriptor, &mut uid, &mut gid) } != 0 {
        return Err(RecoveryError::Io(io::Error::last_os_error()));
    }
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut length,
        )
    } != 0
    {
        return Err(RecoveryError::Io(io::Error::last_os_error()));
    }
    let pid = u32::try_from(pid)
        .map_err(|_| RecoveryError::PrivilegedHelper("socket peer PID is invalid".to_owned()))?;
    Ok((uid, pid))
}

fn validate_socket_owner(path: &Path, expected_uid: u32) -> Result<(), RecoveryError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(RecoveryError::PrivilegedHelper(
            "control socket ownership or permissions are invalid".to_owned(),
        ));
    }
    Ok(())
}

fn write_status(
    path: &Path,
    owner_uid: u32,
    state: HelperStatusState,
    detail: Option<String>,
) -> Result<(), RecoveryError> {
    write_json_atomic(
        path,
        &HelperStatus {
            version: MACOS_PRIVILEGED_HELPER_PROTOCOL_VERSION.to_owned(),
            state,
            detail,
        },
    )?;
    chown_path(path, owner_uid)
}

fn wait_for_ready_status(path: &Path, timeout: Duration) -> Result<(), RecoveryError> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::read(path) {
            Ok(bytes) => {
                let status: HelperStatus =
                    serde_json::from_slice(&bytes).map_err(RecoveryError::Json)?;
                if status.version != MACOS_PRIVILEGED_HELPER_PROTOCOL_VERSION {
                    return Err(RecoveryError::PrivilegedHelper(
                        "helper status protocol version is unsupported".to_owned(),
                    ));
                }
                return match status.state {
                    HelperStatusState::Ready => Ok(()),
                    HelperStatusState::Error => Err(RecoveryError::PrivilegedHelper(
                        status
                            .detail
                            .unwrap_or_else(|| "helper startup failed".to_owned()),
                    )),
                };
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(RecoveryError::Io(error)),
        }
        if Instant::now() >= deadline {
            return Err(RecoveryError::PrivilegedHelper(
                "helper did not become ready before the deadline".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn validate_command(frame: &ControlFrame, expected: ControlCommand) -> Result<(), RecoveryError> {
    if frame.version != MACOS_PRIVILEGED_HELPER_PROTOCOL_VERSION || frame.command != expected {
        return Err(RecoveryError::PrivilegedHelper(
            "control socket protocol message is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_response(frame: ResponseFrame, expected: ResponseState) -> Result<(), RecoveryError> {
    if frame.version != MACOS_PRIVILEGED_HELPER_PROTOCOL_VERSION {
        return Err(RecoveryError::PrivilegedHelper(
            "helper response protocol version is unsupported".to_owned(),
        ));
    }
    if frame.state == expected {
        return Ok(());
    }
    Err(RecoveryError::PrivilegedHelper(
        frame
            .detail
            .unwrap_or_else(|| "helper returned an unexpected response".to_owned()),
    ))
}

fn write_response(
    stream: &mut UnixStream,
    state: ResponseState,
    detail: Option<String>,
) -> Result<(), RecoveryError> {
    write_frame(
        stream,
        &ResponseFrame {
            version: MACOS_PRIVILEGED_HELPER_PROTOCOL_VERSION.to_owned(),
            state,
            detail,
        },
    )
}

fn write_frame<T: Serialize>(stream: &mut impl Write, frame: &T) -> Result<(), RecoveryError> {
    serde_json::to_writer(&mut *stream, frame).map_err(RecoveryError::Json)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn read_required_frame<T: DeserializeOwned>(stream: &mut impl Read) -> Result<T, RecoveryError> {
    read_frame(stream)?.ok_or_else(|| {
        RecoveryError::PrivilegedHelper("control socket closed before a response".to_owned())
    })
}

fn read_frame<T: DeserializeOwned>(stream: &mut impl Read) -> Result<Option<T>, RecoveryError> {
    let mut bytes = Vec::with_capacity(128);
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => {
                return Err(RecoveryError::PrivilegedHelper(
                    "control socket closed during a frame".to_owned(),
                ));
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                bytes.push(byte[0]);
                if bytes.len() > MAX_CONTROL_FRAME_BYTES {
                    return Err(RecoveryError::PrivilegedHelper(
                        "control socket frame exceeds 1 KiB".to_owned(),
                    ));
                }
            }
            Err(error) => return Err(RecoveryError::Io(error)),
        }
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(RecoveryError::Json)
}

fn chown_path(path: &Path, owner_uid: u32) -> Result<(), RecoveryError> {
    if fs::symlink_metadata(path)?.uid() == owner_uid {
        return Ok(());
    }
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        RecoveryError::PrivilegedHelper("helper path contains a null byte".to_owned())
    })?;
    if unsafe { libc::chown(path.as_ptr(), owner_uid, libc::gid_t::MAX) } != 0 {
        return Err(RecoveryError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

struct HelperArtifactCleanup {
    status_path: PathBuf,
    socket_path: PathBuf,
}

impl HelperArtifactCleanup {
    fn new(status_path: &Path, socket_path: &Path) -> Self {
        Self {
            status_path: status_path.to_owned(),
            socket_path: socket_path.to_owned(),
        }
    }
}

impl Drop for HelperArtifactCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.status_path);
        let _ = fs::remove_file(&self.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_endpoint_accepts_only_explicit_loopback_http() {
        for endpoint in ["http://127.0.0.1:43125", "http://[::1]:43125"] {
            assert!(helper_proxy_settings(endpoint).is_ok(), "{endpoint}");
        }
        for endpoint in [
            "http://127.0.0.1",
            "https://127.0.0.1:43125",
            "http://proxy.example:43125",
            "http://user@127.0.0.1:43125",
            "http://127.0.0.1:43125/path",
        ] {
            assert!(helper_proxy_settings(endpoint).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn helper_artifact_names_share_a_restricted_nonce() {
        let status = Path::new(".codeischeap-proxy-helper-session-123.status");
        let socket = Path::new("codeischeap-proxy-helper-session-123.sock");
        assert_eq!(
            helper_nonce(status, HELPER_STATUS_PREFIX, HELPER_STATUS_SUFFIX).unwrap(),
            helper_nonce(socket, HELPER_SOCKET_PREFIX, HELPER_SOCKET_SUFFIX).unwrap()
        );
        for invalid in [
            ".codeischeap-proxy-helper-.status",
            ".codeischeap-proxy-helper-../escape.status",
            ".codeischeap-proxy-helper-session_123.status",
        ] {
            assert!(
                helper_nonce(
                    Path::new(invalid),
                    HELPER_STATUS_PREFIX,
                    HELPER_STATUS_SUFFIX
                )
                .is_err(),
                "{invalid}"
            );
        }
    }
}
