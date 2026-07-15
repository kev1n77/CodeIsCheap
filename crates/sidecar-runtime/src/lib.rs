//! Verified loading and least-environment process lifecycle for capture sidecars.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};

pub const SIDECAR_MANIFEST_VERSION: &str = "0.1";
pub const CAPTURE_CONTRACT_VERSION: &str = "0.1";
pub const MITMPROXY_VERSION: &str = "12.2.3";
pub const SIDECAR_NAME: &str = "codeischeap-mitmproxy";
pub const MANIFEST_FILENAME: &str = "sidecar-manifest.json";

const CAPTURE_ENVIRONMENT: [&str; 4] = [
    "CIC_CAPTURE_HOSTS",
    "CIC_CAPTURE_IPC_ADDR",
    "CIC_CAPTURE_IPC_TOKEN",
    "CIC_CAPTURE_POLICY_PATH",
];

#[derive(Debug)]
pub enum SidecarError {
    Io(io::Error),
    Json(serde_json::Error),
    UnsupportedPlatform,
    InvalidManifest(String),
    InvalidBundlePath(String),
    MissingBundleFile(String),
    BundleFileIsSymlink(String),
    SizeMismatch(String),
    HashMismatch(String),
    TargetMismatch { expected: String, actual: String },
    SignatureRequired,
    InvalidLaunchConfig(String),
    ProcessExited(Option<i32>),
    StartupTimeout(Duration),
}

impl fmt::Display for SidecarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "sidecar I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "sidecar metadata is invalid JSON: {error}"),
            Self::UnsupportedPlatform => write!(formatter, "sidecar platform is unsupported"),
            Self::InvalidManifest(detail) => {
                write!(formatter, "sidecar manifest is invalid: {detail}")
            }
            Self::InvalidBundlePath(name) => {
                write!(formatter, "sidecar bundle path is invalid: {name}")
            }
            Self::MissingBundleFile(name) => {
                write!(formatter, "sidecar bundle file is missing: {name}")
            }
            Self::BundleFileIsSymlink(name) => write!(
                formatter,
                "sidecar bundle file must not be a symlink: {name}"
            ),
            Self::SizeMismatch(name) => {
                write!(formatter, "sidecar bundle file size does not match: {name}")
            }
            Self::HashMismatch(name) => {
                write!(formatter, "sidecar bundle file hash does not match: {name}")
            }
            Self::TargetMismatch { expected, actual } => {
                write!(formatter, "sidecar target is {actual}, expected {expected}")
            }
            Self::SignatureRequired => write!(
                formatter,
                "sidecar release requires a valid platform signature"
            ),
            Self::InvalidLaunchConfig(detail) => write!(
                formatter,
                "sidecar launch configuration is invalid: {detail}"
            ),
            Self::ProcessExited(code) => write!(
                formatter,
                "sidecar exited before accepting connections with code {code:?}"
            ),
            Self::StartupTimeout(timeout) => write!(
                formatter,
                "sidecar did not accept connections within {} ms",
                timeout.as_millis()
            ),
        }
    }
}

impl std::error::Error for SidecarError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for SidecarError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for SidecarError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleRequirements {
    pub require_platform_signature: bool,
}

impl BundleRequirements {
    #[must_use]
    pub const fn development() -> Self {
        Self {
            require_platform_signature: false,
        }
    }

    #[must_use]
    pub const fn release() -> Self {
        Self {
            require_platform_signature: true,
        }
    }
}

#[derive(Debug)]
pub struct SidecarBundle {
    root: PathBuf,
    executable: PathBuf,
    policy: PathBuf,
    sbom: PathBuf,
    manifest: SidecarManifest,
}

impl SidecarBundle {
    pub fn load(
        root: impl AsRef<Path>,
        requirements: BundleRequirements,
    ) -> Result<Self, SidecarError> {
        let root = root.as_ref().to_path_buf();
        let manifest_path = checked_bundle_file(&root, MANIFEST_FILENAME)?;
        let manifest: SidecarManifest = serde_json::from_reader(File::open(manifest_path)?)?;
        validate_manifest(&manifest, requirements)?;

        let executable = checked_bundle_file(&root, &manifest.artifact.file)?;
        validate_size_and_hash(&executable, &manifest.artifact)?;
        let policy = checked_bundle_file(&root, &manifest.capture_contract.policy_file)?;
        validate_hash(
            &policy,
            &manifest.capture_contract.policy_sha256,
            &manifest.capture_contract.policy_file,
        )?;
        let sbom = checked_bundle_file(&root, &manifest.sbom.file)?;
        validate_hash(&sbom, &manifest.sbom.sha256, &manifest.sbom.file)?;
        validate_sbom(&sbom)?;

        Ok(Self {
            root,
            executable,
            policy,
            sbom,
            manifest,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    #[must_use]
    pub fn policy(&self) -> &Path {
        &self.policy
    }

    #[must_use]
    pub fn sbom(&self) -> &Path {
        &self.sbom
    }

    #[must_use]
    pub fn target_triple(&self) -> &str {
        &self.manifest.target_triple
    }

    pub fn command(&self, config: &SidecarLaunchConfig) -> Result<Command, SidecarError> {
        config.validate()?;
        fs::create_dir_all(&config.confdir)?;
        let mut command = Command::new(&self.executable);
        command.env_clear();
        for key in inherited_environment_keys() {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .env("CIC_CAPTURE_IPC_ADDR", config.ipc_addr.to_string())
            .env("CIC_CAPTURE_IPC_TOKEN", &config.ipc_token)
            .env("CIC_CAPTURE_HOSTS", config.target_hosts.join(","))
            .env("CIC_CAPTURE_POLICY_PATH", &self.policy)
            .args([
                OsStr::new("--listen-host"),
                OsStr::new(&config.listen_addr.ip().to_string()),
                OsStr::new("--listen-port"),
                OsStr::new(&config.listen_addr.port().to_string()),
                OsStr::new("--set"),
                OsStr::new(&format!("confdir={}", config.confdir.display())),
                OsStr::new("--set"),
                OsStr::new("termlog_verbosity=error"),
            ])
            .current_dir(&config.confdir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for host in &config.target_hosts {
            command.arg("--allow-hosts").arg(allow_host_pattern(host));
        }
        #[cfg(unix)]
        command.process_group(0);
        Ok(command)
    }

    pub fn launch(
        &self,
        config: &SidecarLaunchConfig,
        startup_timeout: Duration,
    ) -> Result<SidecarProcess, SidecarError> {
        let mut child = self.command(config)?.spawn()?;
        #[cfg(windows)]
        let job = match WindowsJob::assign(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SidecarError::Io(error));
            }
        };
        let started = Instant::now();
        while started.elapsed() < startup_timeout {
            if let Some(status) = child.try_wait()? {
                #[cfg(unix)]
                let _ = terminate_process_group(child.id());
                return Err(SidecarError::ProcessExited(status.code()));
            }
            if TcpStream::connect_timeout(&config.listen_addr, Duration::from_millis(100)).is_ok() {
                return Ok(SidecarProcess {
                    child: Some(child),
                    endpoint: config.listen_addr,
                    #[cfg(windows)]
                    job: Some(job),
                });
            }
            thread::sleep(Duration::from_millis(50));
        }
        stop_spawned_process(&mut child);
        Err(SidecarError::StartupTimeout(startup_timeout))
    }
}

pub struct SidecarProcess {
    child: Option<Child>,
    endpoint: SocketAddr,
    #[cfg(windows)]
    job: Option<WindowsJob>,
}

impl SidecarProcess {
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn stop(&mut self) -> Result<(), SidecarError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        #[cfg(windows)]
        drop(self.job.take());
        #[cfg(unix)]
        let process_group_error = terminate_process_group(child.id()).err();
        if child.try_wait()?.is_none() {
            child.kill()?;
        }
        child.wait()?;
        #[cfg(unix)]
        if let Some(error) = process_group_error {
            return Err(error);
        }
        Ok(())
    }
}

fn stop_spawned_process(child: &mut Child) {
    #[cfg(unix)]
    let _ = terminate_process_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_process_group(process_id: u32) -> Result<(), SidecarError> {
    let process_group = i32::try_from(process_id).map_err(|_| {
        SidecarError::InvalidLaunchConfig("sidecar process ID is invalid".to_owned())
    })?;
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(SidecarError::Io(error))
    }
}

#[cfg(windows)]
struct WindowsJob(OwnedHandle);

#[cfg(windows)]
impl WindowsJob {
    fn assign(child: &Child) -> io::Result<Self> {
        let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw_job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw_job.cast()) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job.handle(),
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                u32::try_from(std::mem::size_of_val(&limits)).expect("job limits fit in u32"),
            )
        };
        if configured == 0 {
            return Err(io::Error::last_os_error());
        }
        let assigned = unsafe {
            AssignProcessToJobObject(
                job.handle(),
                child.as_raw_handle().cast::<std::ffi::c_void>(),
            )
        };
        if assigned == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    fn handle(&self) -> HANDLE {
        self.0.as_raw_handle().cast()
    }
}

impl Drop for SidecarProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub struct SidecarLaunchConfig {
    pub ipc_addr: SocketAddr,
    ipc_token: String,
    pub target_hosts: Vec<String>,
    pub listen_addr: SocketAddr,
    pub confdir: PathBuf,
}

impl SidecarLaunchConfig {
    #[must_use]
    pub fn new(
        ipc_addr: SocketAddr,
        ipc_token: impl Into<String>,
        target_hosts: Vec<String>,
        listen_addr: SocketAddr,
        confdir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            ipc_addr,
            ipc_token: ipc_token.into(),
            target_hosts,
            listen_addr,
            confdir: confdir.into(),
        }
    }

    fn validate(&self) -> Result<(), SidecarError> {
        if !self.ipc_addr.ip().is_loopback() || self.ipc_addr.port() == 0 {
            return Err(SidecarError::InvalidLaunchConfig(
                "capture IPC must use a non-zero loopback address".to_owned(),
            ));
        }
        if !self.listen_addr.ip().is_loopback() || self.listen_addr.port() == 0 {
            return Err(SidecarError::InvalidLaunchConfig(
                "proxy listener must use a non-zero loopback address".to_owned(),
            ));
        }
        if self.ipc_token.len() < 16 || self.ipc_token.chars().any(char::is_whitespace) {
            return Err(SidecarError::InvalidLaunchConfig(
                "capture IPC token is too short or contains whitespace".to_owned(),
            ));
        }
        if self.target_hosts.is_empty()
            || self
                .target_hosts
                .iter()
                .any(|host| host != &host.to_ascii_lowercase() || !is_valid_target_host(host))
        {
            return Err(SidecarError::InvalidLaunchConfig(
                "capture hosts must be lowercase DNS names or IP addresses".to_owned(),
            ));
        }
        if !self.confdir.is_absolute() {
            return Err(SidecarError::InvalidLaunchConfig(
                "sidecar configuration directory must be absolute".to_owned(),
            ));
        }
        Ok(())
    }
}

fn allow_host_pattern(host: &str) -> String {
    format!(r"^{}:\d+$", regex::escape(host))
}

fn is_valid_target_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.contains(',')
        || host.chars().any(char::is_whitespace)
        || host.ends_with('.')
    {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

impl fmt::Debug for SidecarLaunchConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SidecarLaunchConfig")
            .field("ipc_addr", &self.ipc_addr)
            .field("ipc_token", &"[REDACTED]")
            .field("target_hosts", &self.target_hosts)
            .field("listen_addr", &self.listen_addr)
            .field("confdir", &self.confdir)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct SidecarManifest {
    schema_version: String,
    name: String,
    version: String,
    target_triple: String,
    mitmproxy_version: String,
    artifact: Artifact,
    capture_contract: CaptureContract,
    sbom: HashedFile,
    signature: Signature,
    integration_probe: IntegrationProbe,
    bundle_ready: bool,
    release_ready: bool,
}

#[derive(Debug, Deserialize)]
struct Artifact {
    file: String,
    bytes: u64,
    sha256: String,
    max_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct CaptureContract {
    ipc_protocol: String,
    envelope: String,
    policy: String,
    policy_file: String,
    policy_sha256: String,
    allowed_environment: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HashedFile {
    file: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Signature {
    status: String,
}

#[derive(Debug, Deserialize)]
struct IntegrationProbe {
    started: bool,
    forwarding_preserved: bool,
    credential_canaries_in_envelope: u64,
    prompt_preserved: bool,
    response_preserved: bool,
    compressed_response_preserved: bool,
    stream_credentials_removed: bool,
    non_target_tunnel: bool,
}

fn validate_manifest(
    manifest: &SidecarManifest,
    requirements: BundleRequirements,
) -> Result<(), SidecarError> {
    if manifest.schema_version != SIDECAR_MANIFEST_VERSION
        || manifest.name != SIDECAR_NAME
        || manifest.version != env!("CARGO_PKG_VERSION")
        || manifest.mitmproxy_version != MITMPROXY_VERSION
    {
        return Err(SidecarError::InvalidManifest(
            "component versions do not match the desktop runtime".to_owned(),
        ));
    }
    let expected_target = current_target_triple()?.to_owned();
    if manifest.target_triple != expected_target {
        return Err(SidecarError::TargetMismatch {
            expected: expected_target,
            actual: manifest.target_triple.clone(),
        });
    }
    let expected_artifact = executable_name(&manifest.target_triple);
    if manifest.artifact.file != expected_artifact {
        return Err(SidecarError::InvalidManifest(
            "artifact name does not match the target triple".to_owned(),
        ));
    }
    let contract = &manifest.capture_contract;
    if contract.ipc_protocol != CAPTURE_CONTRACT_VERSION
        || contract.envelope != CAPTURE_CONTRACT_VERSION
        || contract.policy != CAPTURE_CONTRACT_VERSION
    {
        return Err(SidecarError::InvalidManifest(
            "capture contract versions are unsupported".to_owned(),
        ));
    }
    let actual_environment = contract
        .allowed_environment
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_environment != CAPTURE_ENVIRONMENT.into_iter().collect() {
        return Err(SidecarError::InvalidManifest(
            "capture environment contract is broader than expected".to_owned(),
        ));
    }
    let probe = &manifest.integration_probe;
    if !manifest.bundle_ready
        || !probe.started
        || !probe.forwarding_preserved
        || !probe.prompt_preserved
        || !probe.response_preserved
        || !probe.compressed_response_preserved
        || !probe.stream_credentials_removed
        || !probe.non_target_tunnel
        || probe.credential_canaries_in_envelope != 0
    {
        return Err(SidecarError::InvalidManifest(
            "integration probe did not prove a safe bundle".to_owned(),
        ));
    }
    if requirements.require_platform_signature
        && (manifest.signature.status != "valid" || !manifest.release_ready)
    {
        return Err(SidecarError::SignatureRequired);
    }
    Ok(())
}

fn validate_size_and_hash(path: &Path, artifact: &Artifact) -> Result<(), SidecarError> {
    let size = fs::metadata(path)?.len();
    if size != artifact.bytes || size > artifact.max_bytes {
        return Err(SidecarError::SizeMismatch(artifact.file.clone()));
    }
    validate_hash(path, &artifact.sha256, &artifact.file)
}

fn validate_hash(path: &Path, expected: &str, name: &str) -> Result<(), SidecarError> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SidecarError::InvalidManifest(format!(
            "{name} SHA-256 is malformed"
        )));
    }
    let mut source = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual = format!("{:x}", digest.finalize());
    if actual != expected {
        return Err(SidecarError::HashMismatch(name.to_owned()));
    }
    Ok(())
}

fn validate_sbom(path: &Path) -> Result<(), SidecarError> {
    let sbom: serde_json::Value = serde_json::from_reader(File::open(path)?)?;
    if sbom.get("bomFormat").and_then(|value| value.as_str()) != Some("CycloneDX")
        || sbom
            .get("components")
            .and_then(|value| value.as_array())
            .is_none_or(Vec::is_empty)
    {
        return Err(SidecarError::InvalidManifest(
            "CycloneDX SBOM is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn checked_bundle_file(root: &Path, name: &str) -> Result<PathBuf, SidecarError> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(SidecarError::InvalidBundlePath(name.to_owned()));
    }
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => SidecarError::MissingBundleFile(name.to_owned()),
        _ => SidecarError::Io(error),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(SidecarError::BundleFileIsSymlink(name.to_owned()));
    }
    if !metadata.is_file() {
        return Err(SidecarError::MissingBundleFile(name.to_owned()));
    }
    Ok(path)
}

#[must_use]
pub fn executable_name(target_triple: &str) -> String {
    let extension = if target_triple.ends_with("windows-msvc") {
        ".exe"
    } else {
        ""
    };
    format!("{SIDECAR_NAME}-{target_triple}{extension}")
}

pub fn current_target_triple() -> Result<&'static str, SidecarError> {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Ok("x86_64-pc-windows-msvc")
    } else if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        Ok("aarch64-pc-windows-msvc")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Ok("x86_64-apple-darwin")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok("x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Ok("aarch64-unknown-linux-gnu")
    } else {
        Err(SidecarError::UnsupportedPlatform)
    }
}

fn inherited_environment_keys() -> &'static [&'static str] {
    if cfg!(target_os = "windows") {
        &["SystemRoot", "WINDIR", "TEMP", "TMP"]
    } else {
        &["TMPDIR"]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::net::TcpListener;
    use std::process::Command;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn bundle(signature: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempdir().expect("bundle directory");
        let root = directory.path().to_path_buf();
        let target = current_target_triple().expect("test platform");
        let artifact_name = executable_name(target);
        let artifact = b"synthetic-sidecar";
        let policy = br#"{"version":"0.1"}"#;
        let sbom = br#"{"bomFormat":"CycloneDX","components":[{"name":"mitmproxy"}]}"#;
        fs::write(root.join(&artifact_name), artifact).expect("artifact");
        fs::write(root.join("capture-policy.v0.1.json"), policy).expect("policy");
        fs::write(root.join("sidecar-sbom.cdx.json"), sbom).expect("sbom");
        let manifest = json!({
            "schema_version": "0.1",
            "name": SIDECAR_NAME,
            "version": env!("CARGO_PKG_VERSION"),
            "target_triple": target,
            "mitmproxy_version": MITMPROXY_VERSION,
            "artifact": {
                "file": artifact_name,
                "bytes": artifact.len(),
                "sha256": sha256(artifact),
                "max_bytes": 1024
            },
            "capture_contract": {
                "ipc_protocol": "0.1",
                "envelope": "0.1",
                "policy": "0.1",
                "policy_file": "capture-policy.v0.1.json",
                "policy_sha256": sha256(policy),
                "allowed_environment": CAPTURE_ENVIRONMENT
            },
            "sbom": {"file": "sidecar-sbom.cdx.json", "sha256": sha256(sbom)},
            "signature": {"status": signature},
            "integration_probe": {
                "started": true,
                "forwarding_preserved": true,
                "credential_canaries_in_envelope": 0,
                "prompt_preserved": true,
                "response_preserved": true,
                "compressed_response_preserved": true,
                "stream_credentials_removed": true,
                "non_target_tunnel": true
            },
            "bundle_ready": true,
            "release_ready": signature == "valid"
        });
        fs::write(
            root.join(MANIFEST_FILENAME),
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("manifest file");
        (directory, root)
    }

    #[test]
    fn development_bundle_verifies_every_file_and_contract() {
        let (_directory, root) = bundle("unsigned");
        let loaded = SidecarBundle::load(&root, BundleRequirements::development())
            .expect("development bundle must load");
        assert_eq!(loaded.target_triple(), current_target_triple().unwrap());
        assert_eq!(loaded.root(), root);
        assert!(loaded.policy().ends_with("capture-policy.v0.1.json"));
        assert!(loaded.sbom().ends_with("sidecar-sbom.cdx.json"));
    }

    #[test]
    fn release_bundle_requires_signature_and_rejects_tampering() {
        let (_directory, root) = bundle("unsigned");
        assert!(matches!(
            SidecarBundle::load(&root, BundleRequirements::release()),
            Err(SidecarError::SignatureRequired)
        ));

        fs::write(
            root.join(executable_name(current_target_triple().unwrap())),
            b"tampered",
        )
        .expect("tamper artifact");
        assert!(matches!(
            SidecarBundle::load(&root, BundleRequirements::development()),
            Err(SidecarError::SizeMismatch(_)) | Err(SidecarError::HashMismatch(_))
        ));
    }

    #[test]
    fn command_contains_only_explicit_capture_and_platform_environment() {
        let (_directory, root) = bundle("unsigned");
        let loaded = SidecarBundle::load(&root, BundleRequirements::development()).unwrap();
        let confdir = root.join("conf");
        let config = SidecarLaunchConfig::new(
            "127.0.0.1:41001".parse().unwrap(),
            "synthetic-token-123456",
            vec!["api.openai.com".to_owned(), "api.anthropic.com".to_owned()],
            "127.0.0.1:41002".parse().unwrap(),
            &confdir,
        );

        let command = loaded.command(&config).expect("command must build");
        assert_eq!(command.get_program(), loaded.executable());
        assert_eq!(command.get_current_dir(), Some(confdir.as_path()));
        let environment = command
            .get_envs()
            .filter_map(|(name, value)| value.map(|value| (name, value)))
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect::<BTreeMap<OsString, OsString>>();
        assert_eq!(
            environment.get(OsStr::new("CIC_CAPTURE_IPC_TOKEN")),
            Some(&OsString::from("synthetic-token-123456"))
        );
        assert_eq!(
            environment.get(OsStr::new("CIC_CAPTURE_HOSTS")),
            Some(&OsString::from("api.openai.com,api.anthropic.com"))
        );
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--allow-hosts", r"^api\.openai\.com:\d+$"])
        );
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["--allow-hosts", r"^api\.anthropic\.com:\d+$"])
        );
        let allowed = inherited_environment_keys()
            .iter()
            .copied()
            .chain(CAPTURE_ENVIRONMENT)
            .map(OsStr::new)
            .collect::<BTreeSet<_>>();
        assert!(
            environment
                .keys()
                .all(|key| allowed.contains(key.as_os_str()))
        );
        assert!(!format!("{config:?}").contains("synthetic-token-123456"));
    }

    #[test]
    fn launch_configuration_rejects_non_loopback_and_relative_state() {
        let (_directory, root) = bundle("unsigned");
        let loaded = SidecarBundle::load(&root, BundleRequirements::development()).unwrap();
        let invalid = SidecarLaunchConfig::new(
            "0.0.0.0:41001".parse().unwrap(),
            "synthetic-token-123456",
            vec!["api.openai.com".to_owned()],
            "127.0.0.1:41002".parse().unwrap(),
            "relative-conf",
        );
        assert!(matches!(
            loaded.command(&invalid),
            Err(SidecarError::InvalidLaunchConfig(_))
        ));

        for host in ["-api.openai.com", "api.openai.com|.*", "api..openai.com"] {
            let invalid_host = SidecarLaunchConfig::new(
                "127.0.0.1:41001".parse().unwrap(),
                "synthetic-token-123456",
                vec![host.to_owned()],
                "127.0.0.1:41002".parse().unwrap(),
                &root,
            );
            assert!(matches!(
                loaded.command(&invalid_host),
                Err(SidecarError::InvalidLaunchConfig(_))
            ));
        }
    }

    #[test]
    fn allow_host_patterns_are_anchored_and_escape_regex_metacharacters() {
        assert_eq!(
            allow_host_pattern("api.openai.com"),
            r"^api\.openai\.com:\d+$"
        );
        assert_eq!(allow_host_pattern("127.0.0.1"), r"^127\.0\.0\.1:\d+$");
    }

    #[test]
    fn launch_starts_a_verified_process_without_inheriting_unapproved_environment() {
        let (_directory, root) = bundle("unsigned");
        let source = root.join("fixture.rs");
        fs::write(
            &source,
            r#"
use std::env;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--descendant") {
        let port = args[2].parse::<u16>().unwrap();
        let confdir = PathBuf::from(&args[3]);
        let _listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        fs::write(confdir.join("descendant-ready.txt"), port.to_string()).unwrap();
        thread::sleep(Duration::from_secs(30));
        return;
    }
    let host = args.windows(2).find(|pair| pair[0] == "--listen-host").unwrap()[1].clone();
    let port = args.windows(2).find(|pair| pair[0] == "--listen-port").unwrap()[1].clone();
    let confdir = args.iter().find_map(|arg| arg.strip_prefix("confdir=")).unwrap();
    let descendant_port = env::var("CIC_CAPTURE_IPC_TOKEN").unwrap().rsplit('-').next().unwrap().parse::<u16>().unwrap();
    let mut environment = env::vars().collect::<Vec<_>>();
    environment.sort();
    fs::write(
        PathBuf::from(confdir).join("observed-environment.txt"),
        environment.into_iter().map(|(key, value)| format!("{key}={value}\n")).collect::<String>(),
    ).unwrap();
    Command::new(env::current_exe().unwrap())
        .arg("--descendant")
        .arg(descendant_port.to_string())
        .arg(confdir)
        .spawn()
        .unwrap();
    let listener = TcpListener::bind(format!("{host}:{port}")).unwrap();
    let _ = listener.accept();
    thread::sleep(Duration::from_secs(30));
}
"#,
        )
        .expect("fixture source");
        let executable = root.join(executable_name(current_target_triple().unwrap()));
        assert!(
            Command::new("rustc")
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .status()
                .expect("rustc must run")
                .success()
        );
        let artifact = fs::read(&executable).expect("compiled fixture");
        let manifest_path = root.join(MANIFEST_FILENAME);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["artifact"]["bytes"] = artifact.len().into();
        manifest["artifact"]["sha256"] = sha256(&artifact).into();
        manifest["artifact"]["max_bytes"] = (artifact.len() + 1).into();
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let bundle = SidecarBundle::load(&root, BundleRequirements::development()).unwrap();
        let ipc_port = free_port();
        let listen_port = free_port();
        let descendant_port = free_port();
        let confdir = root.join("runtime-conf");
        let token = format!("runtime-token-123456-{descendant_port}");
        let config = SidecarLaunchConfig::new(
            format!("127.0.0.1:{ipc_port}").parse().unwrap(),
            &token,
            vec!["api.openai.com".to_owned()],
            format!("127.0.0.1:{listen_port}").parse().unwrap(),
            &confdir,
        );

        let mut process = bundle
            .launch(&config, Duration::from_secs(5))
            .expect("verified fixture must start");
        assert_eq!(process.endpoint(), config.listen_addr);
        let environment = fs::read_to_string(confdir.join("observed-environment.txt")).unwrap();
        assert!(environment.contains(&format!("CIC_CAPTURE_IPC_TOKEN={token}")));
        assert!(environment.contains("CIC_CAPTURE_HOSTS=api.openai.com"));
        assert!(!environment.lines().any(|line| line.starts_with("PATH=")));
        wait_for_file(&confdir.join("descendant-ready.txt"));
        process.stop().expect("fixture must stop");
        assert!(
            TcpListener::bind(("127.0.0.1", descendant_port)).is_ok(),
            "sidecar descendants must stop with the runtime"
        );
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("ephemeral port")
            .local_addr()
            .expect("local address")
            .port()
    }

    fn wait_for_file(path: &Path) {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if path.is_file() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("fixture did not create {}", path.display());
    }
}
