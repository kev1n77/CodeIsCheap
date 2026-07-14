//! Transactional proxy snapshots and an out-of-process recovery watchdog.
//!
//! Platform backends plug into this state machine. The file backend exists for
//! deterministic crash injection and must not be used as a system proxy backend.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::WindowsProxyBackend;

pub const RECOVERY_JOURNAL_VERSION: &str = "0.1";

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRegistryValue {
    pub name: String,
    pub value_type: u32,
    pub bytes: Vec<u8>,
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
    UnsupportedBackend,
    SnapshotBackendMismatch,
    InvalidProxyEndpoint(String),
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
            Self::UnsupportedBackend => write!(formatter, "proxy recovery backend is unsupported"),
            Self::SnapshotBackendMismatch => {
                write!(formatter, "proxy snapshot does not match its backend")
            }
            Self::InvalidProxyEndpoint(endpoint) => {
                write!(formatter, "proxy endpoint {endpoint} is invalid")
            }
        }
    }
}

impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for RecoveryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
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

        if let Err(error) = backend.apply(&desired) {
            let _ = backend.restore(&original);
            let _ = mark_restored(&journal_path);
            let mut watchdog = watchdog;
            let _ = watchdog.disarm();
            let _ = fs::remove_file(&journal_path);
            return Err(error);
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
        self.restore_inner()
    }

    fn restore_inner(&mut self) -> Result<(), RecoveryError> {
        if self.restored {
            return Ok(());
        }
        self.backend.restore(&self.original)?;
        mark_restored(&self.journal_path)?;
        if let Some(mut watchdog) = self.watchdog.take() {
            watchdog.disarm()?;
        }
        remove_if_exists(&self.journal_path)?;
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

    restore_snapshot(journal_path, &journal)?;
    Ok(true)
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
    }
    let temporary = temporary_path(path);
    let mut file = File::create(&temporary)?;
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
