#![cfg(windows)]

use std::borrow::Cow;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codeischeap_proxy_recovery::{ProxyBackend, ProxySettings, ProxySnapshot, WindowsProxyBackend};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, REG_BINARY};
use winreg::reg_value::RegValue;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn isolated_registry_values_round_trip_exactly() {
    let path = test_registry_path();
    let cleanup = RegistryCleanup(path.clone());
    let root = RegKey::predef(HKEY_CURRENT_USER);
    let (main, _) = root
        .create_subkey(&path)
        .expect("test registry key must create");
    main.set_value("ProxyEnable", &0_u32)
        .expect("ProxyEnable must seed");
    main.set_value("ProxyServer", &"seed.example.test:8080")
        .expect("ProxyServer must seed");
    main.set_value("AutoConfigURL", &"https://seed.example.test/proxy.pac")
        .expect("AutoConfigURL must seed");
    let (connections, _) = main
        .create_subkey("Connections")
        .expect("Connections must create");
    connections
        .set_raw_value(
            "DefaultConnectionSettings",
            &RegValue {
                bytes: Cow::Borrowed(&[1, 2, 3, 4, 5]),
                vtype: REG_BINARY,
            },
        )
        .expect("binary settings must seed");

    let backend =
        WindowsProxyBackend::for_test_registry_path(path.clone()).expect("test backend must build");
    let original = backend.snapshot().expect("snapshot must succeed");
    backend
        .apply(&ProxySettings::Manual {
            http_proxy: "http://127.0.0.1:3210".to_owned(),
            https_proxy: "http://127.0.0.1:3211".to_owned(),
            bypass: vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
        })
        .expect("manual settings must apply");

    assert_eq!(
        main.get_value::<u32, _>("ProxyEnable")
            .expect("ProxyEnable must read"),
        1
    );
    assert_eq!(
        main.get_value::<String, _>("ProxyServer")
            .expect("ProxyServer must read"),
        "http=127.0.0.1:3210;https=127.0.0.1:3211"
    );
    assert!(main.get_raw_value("AutoConfigURL").is_err());

    backend.restore(&original).expect("snapshot must restore");

    assert_eq!(backend.snapshot().expect("snapshot must succeed"), original);
    drop(cleanup);
}

#[test]
fn invalid_proxy_endpoints_are_rejected_before_registry_changes() {
    let path = test_registry_path();
    let cleanup = RegistryCleanup(path.clone());
    let root = RegKey::predef(HKEY_CURRENT_USER);
    root.create_subkey(&path)
        .expect("test registry key must create");
    let backend =
        WindowsProxyBackend::for_test_registry_path(path).expect("test backend must build");
    let original = backend.snapshot().expect("snapshot must succeed");

    let result = backend.apply(&ProxySettings::Manual {
        http_proxy: "http://user:password@127.0.0.1:3210".to_owned(),
        https_proxy: "http://127.0.0.1:3210/path".to_owned(),
        bypass: Vec::new(),
    });

    assert!(result.is_err());
    assert_eq!(backend.snapshot().expect("snapshot must succeed"), original);
    drop(cleanup);
}

#[test]
#[ignore = "mutates the ephemeral runner's real WinINet proxy settings"]
fn real_windows_proxy_is_restored_after_force_kill() {
    let root = test_directory("windows-system");
    let journal = root.join("recovery.json");
    let ready = root.join("ready");
    let backend = WindowsProxyBackend::system();
    let original = backend.snapshot().expect("system snapshot must succeed");
    let mut guard = SystemRecoveryGuard {
        backend: backend.clone(),
        original: original.clone(),
        child: None,
        journal: journal.clone(),
    };
    let port = 30_000 + (std::process::id() % 20_000) as u16;
    let child = Command::new(env!("CARGO_BIN_EXE_proxy-recovery-spike"))
        .arg("hold-windows")
        .arg(&journal)
        .arg(&ready)
        .arg(env!("CARGO_BIN_EXE_proxy-watchdog"))
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("owner process must start");
    guard.child = Some(child);
    wait_until(Duration::from_secs(10), || ready.exists());
    assert_ne!(
        backend.snapshot().expect("changed snapshot must read"),
        original
    );

    let child = guard.child.as_mut().expect("child must exist");
    child.kill().expect("owner must be force killed");
    child.wait().expect("owner must exit");
    guard.child = None;

    wait_until(Duration::from_secs(10), || {
        backend.snapshot().ok() == Some(original.clone()) && !journal.exists()
    });
    fs::remove_dir_all(root).expect("test directory must clean up");
}

struct RegistryCleanup(String);

impl Drop for RegistryCleanup {
    fn drop(&mut self) {
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let _ = root.delete_subkey_all(&self.0);
    }
}

struct SystemRecoveryGuard {
    backend: WindowsProxyBackend,
    original: ProxySnapshot,
    child: Option<Child>,
    journal: PathBuf,
}

impl Drop for SystemRecoveryGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = self.backend.restore(&self.original);
        let _ = fs::remove_file(&self.journal);
    }
}

fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("condition was not met within {timeout:?}");
}

fn test_registry_path() -> String {
    format!(
        r"Software\CodeIsCheap\Tests\proxy-{}-{}",
        std::process::id(),
        unique_suffix()
    )
}

fn test_directory(label: &str) -> PathBuf {
    let path = env::temp_dir().join(format!(
        "codeischeap-{label}-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    fs::create_dir_all(&path).expect("test directory must exist");
    path
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}-{sequence}")
}
