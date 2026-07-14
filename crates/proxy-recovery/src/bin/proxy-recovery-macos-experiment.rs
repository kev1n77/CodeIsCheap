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
use codeischeap_proxy_recovery::{MacOsProxyBackend, ProxyBackend, ProxySnapshot};

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
        .stderr(Stdio::null())
        .spawn()?;
    let mut guard = RecoveryGuard {
        backend: backend.clone(),
        original: original.clone(),
        child: Some(child),
        journal: journal.clone(),
    };

    wait_until(Duration::from_secs(15), || ready.exists())?;
    if backend.snapshot()? == original {
        return Err("macOS proxy settings did not change".into());
    }
    let child = guard.child.as_mut().ok_or("owner process is missing")?;
    child.kill()?;
    child.wait()?;
    guard.child = None;

    wait_until(Duration::from_secs(15), || {
        backend.snapshot().ok() == Some(original.clone()) && !journal.exists()
    })?;
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
fn wait_until(
    timeout: Duration,
    condition: impl Fn() -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("condition was not met within {timeout:?}").into())
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
