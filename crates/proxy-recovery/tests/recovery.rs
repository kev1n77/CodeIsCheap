use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codeischeap_proxy_recovery::{
    FileProxyBackend, JournalStatus, ProxyBackend, ProxySession, ProxySettings, ProxySnapshot,
    RECOVERY_JOURNAL_VERSION, RecoveryJournal, recover_from_journal,
};

fn original_settings() -> ProxySettings {
    ProxySettings::AutoConfig {
        url: "https://config.example.test/proxy.pac".to_owned(),
    }
}

fn desired_settings() -> ProxySettings {
    ProxySettings::Manual {
        http_proxy: "http://127.0.0.1:3210".to_owned(),
        https_proxy: "http://127.0.0.1:3210".to_owned(),
        bypass: vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
    }
}

#[test]
fn normal_restore_returns_to_the_exact_snapshot() {
    let root = test_directory("normal");
    let state = root.join("proxy-state.json");
    let journal = root.join("recovery.json");
    let backend = FileProxyBackend::new(&state);
    backend
        .apply(&original_settings())
        .expect("original state must write");

    let session = ProxySession::begin(
        backend.clone(),
        desired_settings(),
        &journal,
        env!("CARGO_BIN_EXE_proxy-watchdog"),
    )
    .expect("session must begin");
    assert_eq!(file_settings(&backend), desired_settings());

    session.restore().expect("session must restore");

    assert_eq!(file_settings(&backend), original_settings());
    assert!(!journal.exists());
    fs::remove_dir_all(root).expect("test directory must clean up");
}

#[test]
fn watchdog_restores_after_the_owner_is_force_killed() {
    let root = test_directory("force-kill");
    let state = root.join("proxy-state.json");
    let journal = root.join("recovery.json");
    let ready = root.join("ready");
    let backend = FileProxyBackend::new(&state);
    backend
        .apply(&original_settings())
        .expect("original state must write");

    let mut owner = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_proxy-recovery-spike"))
            .arg("hold")
            .arg(&state)
            .arg(&journal)
            .arg(&ready)
            .arg(env!("CARGO_BIN_EXE_proxy-watchdog"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("owner process must start"),
    );
    wait_until(Duration::from_secs(5), || ready.exists());
    assert_eq!(file_settings(&backend), desired_settings());

    owner.0.kill().expect("owner process must be force killed");
    owner.0.wait().expect("owner process must exit");

    wait_until(Duration::from_secs(5), || {
        file_settings(&backend) == original_settings() && !journal.exists()
    });
    fs::remove_dir_all(root).expect("test directory must clean up");
}

#[test]
fn watchdog_uses_the_snapshot_loaded_before_ready() {
    let root = test_directory("journal-tamper");
    let state = root.join("proxy-state.json");
    let unrelated = root.join("unrelated-state.json");
    let journal = root.join("recovery.json");
    let ready = root.join("ready");
    let backend = FileProxyBackend::new(&state);
    let unrelated_backend = FileProxyBackend::new(&unrelated);
    backend
        .apply(&original_settings())
        .expect("original state must write");
    unrelated_backend
        .apply(&ProxySettings::Disabled)
        .expect("unrelated state must write");

    let mut owner = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_proxy-recovery-spike"))
            .arg("hold")
            .arg(&state)
            .arg(&journal)
            .arg(&ready)
            .arg(env!("CARGO_BIN_EXE_proxy-watchdog"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("owner process must start"),
    );
    wait_until(Duration::from_secs(5), || ready.exists());

    let mut tampered: RecoveryJournal =
        serde_json::from_slice(&fs::read(&journal).expect("journal must read"))
            .expect("journal must deserialize");
    tampered.backend = unrelated_backend.descriptor();
    tampered.original = ProxySnapshot::File {
        settings: desired_settings(),
    };
    fs::write(
        &journal,
        serde_json::to_vec_pretty(&tampered).expect("tampered journal must serialize"),
    )
    .expect("tampered journal must write");

    owner.0.kill().expect("owner process must be force killed");
    owner.0.wait().expect("owner process must exit");

    wait_until(Duration::from_secs(5), || {
        file_settings(&backend) == original_settings() && !journal.exists()
    });
    assert_eq!(file_settings(&unrelated_backend), ProxySettings::Disabled);
    fs::remove_dir_all(root).expect("test directory must clean up");
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn startup_recovery_repairs_an_armed_journal() {
    let root = test_directory("startup");
    let state = root.join("proxy-state.json");
    let journal = root.join("recovery.json");
    let backend = FileProxyBackend::new(&state);
    backend
        .apply(&original_settings())
        .expect("original state must write");
    backend
        .apply(&desired_settings())
        .expect("desired state must write");
    let recovery = RecoveryJournal {
        version: RECOVERY_JOURNAL_VERSION.to_owned(),
        transaction_id: "startup-recovery-test".to_owned(),
        owner_pid: u32::MAX,
        status: JournalStatus::Armed,
        backend: backend.descriptor(),
        original: ProxySnapshot::File {
            settings: original_settings(),
        },
        desired: desired_settings(),
    };
    fs::write(
        &journal,
        serde_json::to_vec_pretty(&recovery).expect("journal must serialize"),
    )
    .expect("journal must write");

    assert!(recover_from_journal(&journal).expect("startup recovery must succeed"));
    assert_eq!(file_settings(&backend), original_settings());
    assert!(!journal.exists());
    fs::remove_dir_all(root).expect("test directory must clean up");
}

fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("condition was not met within {timeout:?}");
}

fn file_settings(backend: &FileProxyBackend) -> ProxySettings {
    match backend.snapshot().expect("state must read") {
        ProxySnapshot::File { settings } => settings,
        ProxySnapshot::Windows { .. } => panic!("file backend returned a Windows snapshot"),
    }
}

fn test_directory(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "codeischeap-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("test directory must exist");
    path
}
