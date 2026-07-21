//! Transactional proxy snapshots and an out-of-process recovery watchdog.
//!
//! Platform backends plug into this state machine. The file backend exists for
//! deterministic crash injection and must not be used as a system proxy backend.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

use serde::{Deserialize, Serialize};

#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_privileged;

#[cfg(windows)]
pub use windows::WindowsProxyBackend;

#[cfg(target_os = "macos")]
pub use macos::MacOsProxyBackend;
#[cfg(target_os = "macos")]
pub use macos_privileged::{
    MacOsPrivilegedProxySession, recover_macos_proxy_journal_with_authorization,
    run_macos_privileged_proxy_helper, run_macos_privileged_proxy_recovery,
    run_macos_proxy_helper_session,
};

pub const RECOVERY_JOURNAL_VERSION: &str = "0.1";
pub const MACOS_PRIVILEGED_HELPER_PROTOCOL_VERSION: &str = "0.1";
pub const MACOS_PROXY_RECOVERY_JOURNAL_FILENAME: &str = "proxy-recovery.v0.1.json";

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ProxySettings {
    Disabled,
    Manual {
        http_proxy: String,
        https_proxy: String,
        #[serde(default)]
        bypass: Vec<String>,
    },
    AutoConfig {
        url: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendDescriptor {
    File { state_path: PathBuf },
    Windows { registry_path: String, notify: bool },
    MacOs { networksetup_path: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case")]
pub enum ProxySnapshot {
    File {
        settings: ProxySettings,
    },
    Windows {
        main_values: Vec<WindowsRegistryValue>,
        connection_values: Vec<WindowsRegistryValue>,
    },
    MacOs {
        services: Vec<MacOsNetworkService>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRegistryValue {
    pub name: String,
    pub value_type: u32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsNetworkService {
    pub name: String,
    pub web_proxy: MacOsManualProxy,
    pub secure_web_proxy: MacOsManualProxy,
    pub auto_config: MacOsAutoConfig,
    pub auto_discovery_enabled: bool,
    #[serde(default)]
    pub bypass_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsManualProxy {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
    pub authenticated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsAutoConfig {
    pub enabled: bool,
    pub url: Option<String>,
}

pub trait ProxyBackend {
    fn descriptor(&self) -> BackendDescriptor;
    fn snapshot(&self) -> Result<ProxySnapshot, RecoveryError>;
    fn apply(&self, settings: &ProxySettings) -> Result<(), RecoveryError>;
    fn restore(&self, snapshot: &ProxySnapshot) -> Result<(), RecoveryError>;
}

#[derive(Debug, Clone)]
pub struct FileProxyBackend {
    state_path: PathBuf,
}

impl FileProxyBackend {
    pub fn new(state_path: impl Into<PathBuf>) -> Self {
        Self {
            state_path: state_path.into(),
        }
    }
}

impl ProxyBackend for FileProxyBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor::File {
            state_path: self.state_path.clone(),
        }
    }

    fn snapshot(&self) -> Result<ProxySnapshot, RecoveryError> {
        let bytes = fs::read(&self.state_path).map_err(RecoveryError::Io)?;
        let settings = serde_json::from_slice(&bytes).map_err(RecoveryError::Json)?;
        Ok(ProxySnapshot::File { settings })
    }

    fn apply(&self, settings: &ProxySettings) -> Result<(), RecoveryError> {
        write_json_atomic(&self.state_path, settings)
    }

    fn restore(&self, snapshot: &ProxySnapshot) -> Result<(), RecoveryError> {
        let ProxySnapshot::File { settings } = snapshot else {
            return Err(RecoveryError::SnapshotBackendMismatch);
        };
        self.apply(settings)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalStatus {
    Armed,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryJournal {
    pub version: String,
    pub transaction_id: String,
    pub owner_pid: u32,
    pub status: JournalStatus,
    pub backend: BackendDescriptor,
    pub original: ProxySnapshot,
    pub desired: ProxySettings,
}

#[derive(Debug)]
pub enum RecoveryError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidJournalVersion(String),
    WatchdogDidNotBecomeReady,
    WatchdogExitedEarly,
    OwnerStillRunning(u32),
    UnsupportedBackend,
    SnapshotBackendMismatch,
    InvalidProxyEndpoint(String),
    PlatformCommandFailed(String),
    PlatformOutputInvalid(String),
    AuthenticatedProxyUnsupported(String),
    PrivilegedHelper(String),
    OperationFailed {
        operation: &'static str,
        source: Box<RecoveryError>,
    },
    RestoreRetryFailed {
        first: Box<RecoveryError>,
        retry: Box<RecoveryError>,
    },
    RollbackRecoveryFailed {
        apply: Box<RecoveryError>,
        rollback: Box<RecoveryError>,
        recovery: Box<RecoveryError>,
    },
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "proxy recovery I/O failed: {error}"),
            Self::Json(_) => write!(formatter, "proxy recovery data is invalid"),
            Self::InvalidJournalVersion(version) => {
                write!(
                    formatter,
                    "proxy recovery journal version {version} is unsupported"
                )
            }
            Self::WatchdogDidNotBecomeReady => {
                write!(formatter, "proxy watchdog did not become ready")
            }
            Self::WatchdogExitedEarly => write!(formatter, "proxy watchdog exited before arming"),
            Self::OwnerStillRunning(pid) => {
                write!(
                    formatter,
                    "proxy recovery owner process {pid} is still running"
                )
            }
            Self::UnsupportedBackend => write!(formatter, "proxy recovery backend is unsupported"),
            Self::SnapshotBackendMismatch => {
                write!(formatter, "proxy snapshot does not match its backend")
            }
            Self::InvalidProxyEndpoint(endpoint) => {
                write!(formatter, "proxy endpoint {endpoint} is invalid")
            }
            Self::PlatformCommandFailed(operation) => {
                write!(formatter, "platform proxy command {operation} failed")
            }
            Self::PlatformOutputInvalid(operation) => {
                write!(
                    formatter,
                    "platform proxy output for {operation} is invalid"
                )
            }
            Self::AuthenticatedProxyUnsupported(service) => {
                write!(
                    formatter,
                    "authenticated proxy on service {service} cannot be restored safely"
                )
            }
            Self::PrivilegedHelper(detail) => {
                write!(formatter, "privileged proxy helper failed: {detail}")
            }
            Self::OperationFailed { operation, source } => {
                write!(
                    formatter,
                    "proxy recovery failed while {operation}: {source}"
                )
            }
            Self::RestoreRetryFailed { first, retry } => {
                write!(
                    formatter,
                    "proxy recovery failed, then its idempotent retry also failed ({first}; retry: {retry})"
                )
            }
            Self::RollbackRecoveryFailed {
                apply,
                rollback,
                recovery,
            } => {
                write!(
                    formatter,
                    "proxy apply failed ({apply}); synchronous rollback failed ({rollback}); watchdog recovery failed ({recovery})"
                )
            }
        }
    }
}

impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::OperationFailed { source, .. } => Some(source.as_ref()),
            Self::RestoreRetryFailed { retry, .. } => Some(retry.as_ref()),
            Self::RollbackRecoveryFailed { apply, .. } => Some(apply.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for RecoveryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl RecoveryError {
    fn while_doing(self, operation: &'static str) -> Self {
        Self::OperationFailed {
            operation,
            source: Box::new(self),
        }
    }
}

pub struct ProxySession<B: ProxyBackend> {
    backend: B,
    journal_path: PathBuf,
    original: ProxySnapshot,
    watchdog: Option<WatchdogHandle>,
    restored: bool,
}

impl<B: ProxyBackend> ProxySession<B> {
    pub fn begin(
        backend: B,
        desired: ProxySettings,
        journal_path: impl Into<PathBuf>,
        watchdog_executable: impl AsRef<Path>,
    ) -> Result<Self, RecoveryError> {
        let journal_path = journal_path.into();
        let original = backend.snapshot()?;
        let journal = RecoveryJournal {
            version: RECOVERY_JOURNAL_VERSION.to_owned(),
            transaction_id: transaction_id(),
            owner_pid: std::process::id(),
            status: JournalStatus::Armed,
            backend: backend.descriptor(),
            original: original.clone(),
            desired: desired.clone(),
        };
        write_json_atomic(&journal_path, &journal)?;

        let watchdog = match WatchdogHandle::spawn(watchdog_executable.as_ref(), &journal_path) {
            Ok(watchdog) => watchdog,
            Err(error) => {
                let _ = fs::remove_file(&journal_path);
                return Err(error);
            }
        };

        if let Err(apply_error) = backend.apply(&desired) {
            if let Err(rollback_error) = backend.restore(&original) {
                let mut watchdog = watchdog;
                return match watchdog.recover_now() {
                    Ok(()) => Err(apply_error),
                    Err(recovery_error) => Err(RecoveryError::RollbackRecoveryFailed {
                        apply: Box::new(apply_error),
                        rollback: Box::new(rollback_error),
                        recovery: Box::new(recovery_error),
                    }),
                };
            }
            let _ = mark_restored(&journal_path);
            let mut watchdog = watchdog;
            let _ = watchdog.disarm();
            let _ = fs::remove_file(&journal_path);
            return Err(apply_error);
        }

        Ok(Self {
            backend,
            journal_path,
            original,
            watchdog: Some(watchdog),
            restored: false,
        })
    }

    pub fn restore(mut self) -> Result<(), RecoveryError> {
        let first = match self.restore_inner() {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        self.restore_inner()
            .map_err(|retry| RecoveryError::RestoreRetryFailed {
                first: Box::new(first),
                retry: Box::new(retry),
            })
    }

    fn restore_inner(&mut self) -> Result<(), RecoveryError> {
        if self.restored {
            return Ok(());
        }
        self.backend
            .restore(&self.original)
            .map_err(|error| error.while_doing("restoring the original proxy snapshot"))?;
        mark_restored(&self.journal_path)
            .map_err(|error| error.while_doing("marking the recovery journal restored"))?;
        if let Some(watchdog) = self.watchdog.as_mut() {
            watchdog
                .disarm()
                .map_err(|error| error.while_doing("disarming the proxy watchdog"))?;
        }
        self.watchdog = None;
        remove_if_exists(&self.journal_path)
            .map_err(RecoveryError::Io)
            .map_err(|error| error.while_doing("removing the restored recovery journal"))?;
        self.restored = true;
        Ok(())
    }
}

impl<B: ProxyBackend> Drop for ProxySession<B> {
    fn drop(&mut self) {
        let _ = self.restore_inner();
    }
}

struct WatchdogHandle {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl WatchdogHandle {
    fn spawn(executable: &Path, journal_path: &Path) -> Result<Self, RecoveryError> {
        let mut child = Command::new(executable)
            .arg("--journal")
            .arg(journal_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or(RecoveryError::WatchdogExitedEarly)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(RecoveryError::WatchdogExitedEarly)?;
        let mut ready = String::new();
        BufReader::new(stdout).read_line(&mut ready)?;
        if ready.trim() != "ready" {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RecoveryError::WatchdogDidNotBecomeReady);
        }
        Ok(Self {
            child,
            stdin: Some(stdin),
        })
    }

    fn disarm(&mut self) -> Result<(), RecoveryError> {
        if let Some(mut stdin) = self.stdin.take() {
            stdin.write_all(b"disarm\n")?;
            stdin.flush()?;
        }
        let status = self.child.wait()?;
        if !status.success() {
            return Err(RecoveryError::WatchdogExitedEarly);
        }
        Ok(())
    }

    fn recover_now(&mut self) -> Result<(), RecoveryError> {
        drop(self.stdin.take());
        let status = self.child.wait()?;
        if !status.success() {
            return Err(RecoveryError::WatchdogExitedEarly);
        }
        Ok(())
    }
}

pub fn run_watchdog(journal_path: &Path) -> Result<(), RecoveryError> {
    let armed_journal = load_journal(journal_path)?;
    validate_journal(&armed_journal)?;
    println!("ready");
    io::stdout().flush()?;

    let mut command = String::new();
    io::stdin().read_to_string(&mut command)?;
    let latest = load_journal(journal_path)?;
    if command.trim() == "disarm" && latest.status == JournalStatus::Restored {
        remove_if_exists(journal_path)?;
        return Ok(());
    }

    restore_snapshot(journal_path, &armed_journal)
}

pub fn recover_from_journal(journal_path: &Path) -> Result<bool, RecoveryError> {
    if !journal_path.exists() {
        return Ok(false);
    }
    let journal = load_journal(journal_path)?;
    validate_journal(&journal)?;
    if journal.status == JournalStatus::Restored {
        remove_if_exists(journal_path)?;
        return Ok(false);
    }
    if owner_process_is_running(journal.owner_pid)? {
        return Err(RecoveryError::OwnerStillRunning(journal.owner_pid));
    }

    restore_snapshot(journal_path, &journal)?;
    Ok(true)
}

fn owner_process_is_running(pid: u32) -> Result<bool, RecoveryError> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER,
        };
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if !handle.is_null() {
            unsafe {
                CloseHandle(handle);
            }
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error().map(|value| value as u32) {
            Some(ERROR_ACCESS_DENIED) => Ok(true),
            Some(ERROR_INVALID_PARAMETER) => Ok(false),
            _ => Err(RecoveryError::Io(error)),
        }
    }
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else {
            return Ok(false);
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EPERM) => Ok(true),
            Some(libc::ESRCH) => Ok(false),
            _ => Err(RecoveryError::Io(error)),
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = pid;
        Ok(false)
    }
}

fn restore_snapshot(journal_path: &Path, journal: &RecoveryJournal) -> Result<(), RecoveryError> {
    restore_with_backend(&journal.backend, &journal.original)?;
    let mut restored = journal.clone();
    restored.status = JournalStatus::Restored;
    write_json_atomic(journal_path, &restored)?;
    remove_if_exists(journal_path)?;
    Ok(())
}

fn restore_with_backend(
    descriptor: &BackendDescriptor,
    snapshot: &ProxySnapshot,
) -> Result<(), RecoveryError> {
    match descriptor {
        BackendDescriptor::File { state_path } => {
            FileProxyBackend::new(state_path).restore(snapshot)
        }
        #[cfg(windows)]
        BackendDescriptor::Windows {
            registry_path,
            notify,
        } => {
            WindowsProxyBackend::for_registry_path(registry_path.clone(), *notify).restore(snapshot)
        }
        #[cfg(not(windows))]
        BackendDescriptor::Windows { .. } => Err(RecoveryError::UnsupportedBackend),
        #[cfg(target_os = "macos")]
        BackendDescriptor::MacOs { networksetup_path } => {
            MacOsProxyBackend::for_networksetup_path(networksetup_path.clone())?.restore(snapshot)
        }
        #[cfg(not(target_os = "macos"))]
        BackendDescriptor::MacOs { .. } => Err(RecoveryError::UnsupportedBackend),
    }
}

fn load_journal(path: &Path) -> Result<RecoveryJournal, RecoveryError> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(RecoveryError::Json)
}

fn validate_journal(journal: &RecoveryJournal) -> Result<(), RecoveryError> {
    if journal.version != RECOVERY_JOURNAL_VERSION {
        return Err(RecoveryError::InvalidJournalVersion(
            journal.version.clone(),
        ));
    }
    Ok(())
}

fn mark_restored(path: &Path) -> Result<(), RecoveryError> {
    let mut journal = load_journal(path)?;
    journal.status = JournalStatus::Restored;
    write_json_atomic(path, &journal)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), RecoveryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let (temporary, mut file) = loop {
        let temporary = temporary_path(path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temporary) {
            Ok(file) => break (temporary, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(RecoveryError::Io(error)),
        }
    };
    serde_json::to_writer_pretty(&mut file, value).map_err(RecoveryError::Json)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    replace_file(&temporary, path)?;
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    fs::rename(source, target)
}

#[cfg(windows)]
fn replace_file(source: &Path, target: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("proxy-recovery");
    path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), sequence))
}

fn transaction_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}
