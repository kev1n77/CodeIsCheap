use std::fs;
use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};

use codeischeap_proxy_recovery::{
    FileProxyBackend, JournalStatus, ProxyBackend, ProxySettings, ProxySnapshot,
    RECOVERY_JOURNAL_VERSION, RecoveryJournal,
};
use tempfile::tempdir;

#[test]
fn desktop_binary_restores_an_armed_proxy_journal() {
    let directory = tempdir().expect("test directory");
    let state_path = directory.path().join("proxy-state.json");
    let journal_path = directory.path().join("proxy-recovery.json");
    let backend = FileProxyBackend::new(&state_path);
    let original = ProxySettings::AutoConfig {
        url: "https://config.example.test/proxy.pac".to_owned(),
    };
    let desired = ProxySettings::Manual {
        http_proxy: "http://127.0.0.1:43125".to_owned(),
        https_proxy: "http://127.0.0.1:43125".to_owned(),
        bypass: vec!["localhost".to_owned()],
    };
    backend
        .apply(&original)
        .expect("write original proxy state");
    backend.apply(&desired).expect("write desired proxy state");
    let journal = RecoveryJournal {
        version: RECOVERY_JOURNAL_VERSION.to_owned(),
        transaction_id: "desktop-watchdog-entrypoint".to_owned(),
        owner_pid: std::process::id(),
        status: JournalStatus::Armed,
        backend: backend.descriptor(),
        original: ProxySnapshot::File {
            settings: original.clone(),
        },
        desired,
    };
    fs::write(
        &journal_path,
        serde_json::to_vec_pretty(&journal).expect("serialize recovery journal"),
    )
    .expect("write recovery journal");

    let mut watchdog = Command::new(env!("CARGO_BIN_EXE_codeischeap-desktop"))
        .arg("--journal")
        .arg(&journal_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start desktop watchdog entrypoint");
    let mut ready = String::new();
    BufReader::new(watchdog.stdout.take().expect("watchdog stdout"))
        .read_line(&mut ready)
        .expect("read watchdog readiness");
    assert_eq!(ready.trim(), "ready");
    drop(watchdog.stdin.take());
    assert!(watchdog.wait().expect("watchdog exit").success());

    assert_eq!(
        backend.snapshot().expect("read restored proxy state"),
        ProxySnapshot::File { settings: original }
    );
    assert!(!journal_path.exists());
}
