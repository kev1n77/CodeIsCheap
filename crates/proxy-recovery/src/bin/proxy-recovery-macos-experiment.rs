#[cfg(target_os = "macos")]
use std::env;
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "macos")]
use codeischeap_proxy_recovery::{
    MacOsNetworkService, MacOsProxyBackend, ProxyBackend, ProxySnapshot, recover_from_journal,
};

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = MacOsProxyBackend::system();
    let original = backend.snapshot()?;
    let ProxySnapshot::MacOs { services } = &original else {
        return Err("macOS backend returned a non-macOS snapshot".into());
    };
    if services.is_empty() {
        return Err("macOS runner has no active network services".into());
    }

    let root = experiment_directory();
    fs::create_dir_all(&root)?;
    let journal = root.join("recovery.json");
    let ready = root.join("ready");
    let executable_dir = env::current_exe()?
        .parent()
        .ok_or("experiment executable has no parent directory")?
        .to_owned();
    let watchdog = executable_dir.join("proxy-watchdog");
    let spike = executable_dir.join("proxy-recovery-spike");
    let port = 30_000 + (std::process::id() % 20_000) as u16;
    let child = Command::new(spike)
        .arg("hold-macos")
        .arg(&journal)
        .arg(&ready)
        .arg(&watchdog)
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut guard = RecoveryGuard {
        backend: backend.clone(),
        original: original.clone(),
        child: Some(child),
        journal: journal.clone(),
    };

    wait_for_ready(
        Duration::from_secs(15),
        &ready,
        guard.child.as_mut().ok_or("owner process is missing")?,
    )?;
    if backend.snapshot()? == original {
        return Err("macOS proxy settings did not change".into());
    }
    let child = guard.child.as_mut().ok_or("owner process is missing")?;
    child.kill()?;
    child.wait()?;
    guard.child = None;

    wait_for_restore(Duration::from_secs(15), &backend, &original, &journal)?;
    fs::remove_dir_all(root)?;
    println!("macOS system proxy restored after force-killing the owner process");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("this experiment only runs on macOS".into())
}

#[cfg(target_os = "macos")]
struct RecoveryGuard {
    backend: MacOsProxyBackend,
    original: ProxySnapshot,
    child: Option<Child>,
    journal: PathBuf,
}

#[cfg(target_os = "macos")]
impl Drop for RecoveryGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = self.backend.restore(&self.original);
        let _ = fs::remove_file(&self.journal);
    }
}

#[cfg(target_os = "macos")]
fn wait_for_restore(
    timeout: Duration,
    backend: &MacOsProxyBackend,
    expected: &ProxySnapshot,
    journal: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if backend.snapshot().ok().as_ref() == Some(expected) && !journal.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let actual = backend.snapshot()?;
    let differences = snapshot_differences(expected, &actual);
    let journal_existed = journal.exists();
    let repair = if journal_existed {
        match recover_from_journal(journal) {
            Ok(restored) => format!("startup_repair={restored}"),
            Err(error) => format!("startup_repair_error={error}"),
        }
    } else {
        "startup_repair=not_needed".to_owned()
    };
    Err(format!(
        "macOS restore mismatch fields={}; journal_existed={journal_existed}; {repair}",
        differences.join(",")
    )
    .into())
}

#[cfg(target_os = "macos")]
fn wait_for_ready(
    timeout: Duration,
    ready: &std::path::Path,
    child: &mut Child,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if ready.exists() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(format!("proxy owner exited before ready with {status}").into());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("proxy owner was not ready within {timeout:?}").into())
}

#[cfg(target_os = "macos")]
fn experiment_directory() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    env::temp_dir().join(format!(
        "codeischeap-macos-system-{}-{nanos}",
        std::process::id()
    ))
}

#[cfg(target_os = "macos")]
fn snapshot_differences(expected: &ProxySnapshot, actual: &ProxySnapshot) -> Vec<String> {
    let (ProxySnapshot::MacOs { services: expected }, ProxySnapshot::MacOs { services: actual }) =
        (expected, actual)
    else {
        return vec!["snapshot_platform".to_owned()];
    };
    if expected.len() != actual.len() {
        return vec!["service_count".to_owned()];
    }
    let mut differences = Vec::new();
    for (expected, actual) in expected.iter().zip(actual) {
        if expected.name != actual.name {
            differences.push("service_name".to_owned());
            continue;
        }
        compare_service(expected, actual, &mut differences);
    }
    differences
}

#[cfg(target_os = "macos")]
fn compare_service(
    expected: &MacOsNetworkService,
    actual: &MacOsNetworkService,
    differences: &mut Vec<String>,
) {
    if expected.web_proxy.enabled != actual.web_proxy.enabled {
        differences.push("web_enabled".to_owned());
    }
    if expected.web_proxy.server != actual.web_proxy.server {
        differences.push("web_server".to_owned());
    }
    if expected.web_proxy.port != actual.web_proxy.port {
        differences.push("web_port".to_owned());
    }
    if expected.secure_web_proxy.enabled != actual.secure_web_proxy.enabled {
        differences.push("secure_enabled".to_owned());
    }
    if expected.secure_web_proxy.server != actual.secure_web_proxy.server {
        differences.push("secure_server".to_owned());
    }
    if expected.secure_web_proxy.port != actual.secure_web_proxy.port {
        differences.push("secure_port".to_owned());
    }
    if expected.auto_config.enabled != actual.auto_config.enabled {
        differences.push("auto_config_enabled".to_owned());
    }
    if expected.auto_config.url != actual.auto_config.url {
        differences.push("auto_config_url".to_owned());
    }
    if expected.auto_discovery_enabled != actual.auto_discovery_enabled {
        differences.push("auto_discovery".to_owned());
    }
    if expected.bypass_domains != actual.bypass_domains {
        differences.push("bypass_domains".to_owned());
    }
}
