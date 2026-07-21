use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codeischeap_proxy_recovery::{
    FileProxyBackend, JournalStatus, ProxyBackend, ProxySession, ProxySettings, ProxySnapshot,
    RECOVERY_JOURNAL_VERSION, RecoveryError, RecoveryJournal, recover_from_journal,
};

static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

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

#[derive(Debug, Clone)]
struct ApplyAndRollbackFailureBackend {
    inner: FileProxyBackend,
}

#[derive(Debug, Clone)]
struct FailOnceRestoreBackend {
    inner: FileProxyBackend,
    restore_attempts: Arc<AtomicUsize>,
}

impl ProxyBackend for FailOnceRestoreBackend {
    fn descriptor(&self) -> codeischeap_proxy_recovery::BackendDescriptor {
        self.inner.descriptor()
    }

    fn snapshot(&self) -> Result<ProxySnapshot, RecoveryError> {
        self.inner.snapshot()
    }

    fn apply(&self, settings: &ProxySettings) -> Result<(), RecoveryError> {
        self.inner.apply(settings)
    }

    fn restore(&self, snapshot: &ProxySnapshot) -> Result<(), RecoveryError> {
        if self.restore_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(RecoveryError::PlatformCommandFailed(
                "fault-injected transient restore".to_owned(),
            ));
        }
        self.inner.restore(snapshot)
    }
}

impl ProxyBackend for ApplyAndRollbackFailureBackend {
    fn descriptor(&self) -> codeischeap_proxy_recovery::BackendDescriptor {
        self.inner.descriptor()
    }

    fn snapshot(&self) -> Result<ProxySnapshot, RecoveryError> {
        self.inner.snapshot()
    }

    fn apply(&self, settings: &ProxySettings) -> Result<(), RecoveryError> {
        self.inner.apply(settings)?;
        Err(RecoveryError::PlatformCommandFailed(
            "fault-injected apply".to_owned(),
        ))
    }

    fn restore(&self, _snapshot: &ProxySnapshot) -> Result<(), RecoveryError> {
        Err(RecoveryError::PlatformCommandFailed(
            "fault-injected inline rollback".to_owned(),
        ))
    }
}

#[test]
fn normal_restore_returns_to_the_exact_snapshot() {
    let _lock = PROCESS_TEST_LOCK
        .lock()
        .expect("process test lock must work");
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        assert_eq!(
            fs::metadata(&root)
                .expect("journal directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&journal)
                .expect("journal metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    session.restore().expect("session must restore");

    assert_eq!(file_settings(&backend), original_settings());
    assert!(!journal.exists());
    fs::remove_dir_all(root).expect("test directory must clean up");
}

#[test]
fn transient_restore_failure_is_retried_before_disarming_the_watchdog() {
    let _lock = PROCESS_TEST_LOCK
        .lock()
        .expect("process test lock must work");
    let root = test_directory("restore-retry");
    let state = root.join("proxy-state.json");
    let journal = root.join("recovery.json");
    let inner = FileProxyBackend::new(&state);
    inner
        .apply(&original_settings())
        .expect("original state must write");
    let restore_attempts = Arc::new(AtomicUsize::new(0));
    let backend = FailOnceRestoreBackend {
        inner: inner.clone(),
        restore_attempts: restore_attempts.clone(),
    };

    let session = ProxySession::begin(
        backend,
        desired_settings(),
        &journal,
        env!("CARGO_BIN_EXE_proxy-watchdog"),
    )
    .expect("session must begin");
    session
        .restore()
        .expect("the idempotent retry must restore the session");

    assert_eq!(restore_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(file_settings(&inner), original_settings());
    assert!(!journal.exists());
    fs::remove_dir_all(root).expect("test directory must clean up");
}

#[test]
fn watchdog_recovers_pac_snapshot_when_apply_and_inline_rollback_fail() {
    let _lock = PROCESS_TEST_LOCK
        .lock()
        .expect("process test lock must work");
    let root = test_directory("apply-rollback-failure");
    let state = root.join("proxy-state.json");
    let journal = root.join("recovery.json");
    let inner = FileProxyBackend::new(&state);
    inner
        .apply(&original_settings())
        .expect("PAC state must be seeded");
    let backend = ApplyAndRollbackFailureBackend {
        inner: inner.clone(),
    };

    let error = match ProxySession::begin(
        backend,
        desired_settings(),
        &journal,
        env!("CARGO_BIN_EXE_proxy-watchdog"),
    ) {
        Ok(_) => panic!("fault-injected apply must fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        RecoveryError::PlatformCommandFailed(operation)
            if operation == "fault-injected apply"
    ));
    assert_eq!(file_settings(&inner), original_settings());
    assert!(!journal.exists());
    fs::remove_dir_all(root).expect("test directory must clean up");
}

#[test]
fn watchdog_restores_after_the_owner_is_force_killed() {
    let _lock = PROCESS_TEST_LOCK
        .lock()
        .expect("process test lock must work");
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
    wait_until(Duration::from_secs(15), || ready.exists());
    assert_eq!(file_settings(&backend), desired_settings());

    owner.0.kill().expect("owner process must be force killed");
    owner.0.wait().expect("owner process must exit");

    wait_until(Duration::from_secs(15), || {
        file_settings(&backend) == original_settings() && !journal.exists()
    });
    fs::remove_dir_all(root).expect("test directory must clean up");
}

#[test]
fn watchdog_uses_the_snapshot_loaded_before_ready() {
    let _lock = PROCESS_TEST_LOCK
        .lock()
        .expect("process test lock must work");
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
    wait_until(Duration::from_secs(15), || ready.exists());

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

    wait_until(Duration::from_secs(15), || {
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

#[test]
fn startup_recovery_does_not_override_a_live_owner() {
    let root = test_directory("live-owner");
    let state = root.join("proxy-state.json");
    let journal = root.join("recovery.json");
    let backend = FileProxyBackend::new(&state);
    backend
        .apply(&desired_settings())
        .expect("desired state must write");
    let recovery = RecoveryJournal {
        version: RECOVERY_JOURNAL_VERSION.to_owned(),
        transaction_id: "live-owner-test".to_owned(),
        owner_pid: std::process::id(),
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

    assert!(matches!(
        recover_from_journal(&journal),
        Err(RecoveryError::OwnerStillRunning(pid)) if pid == std::process::id()
    ));
    assert_eq!(file_settings(&backend), desired_settings());
    assert!(journal.exists());
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
        ProxySnapshot::MacOs { .. } => panic!("file backend returned a macOS snapshot"),
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
