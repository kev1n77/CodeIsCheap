#![cfg(target_os = "macos")]

use std::env;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codeischeap_proxy_recovery::{
    FileProxyBackend, MACOS_PROXY_RECOVERY_JOURNAL_FILENAME, MacOsPrivilegedProxySession,
    ProxyBackend, ProxySettings, ProxySnapshot, run_macos_proxy_helper_session,
};

#[test]
fn pid_bound_helper_restores_pac_state_on_command() {
    run_helper_scenario(false);
}

#[test]
fn pid_bound_helper_restores_pac_state_on_disconnect() {
    run_helper_scenario(true);
}

fn run_helper_scenario(disconnect: bool) {
    let root = test_directory(if disconnect { "disconnect" } else { "restore" });
    let state = root.join("proxy-state.json");
    let journal = root.join(MACOS_PROXY_RECOVERY_JOURNAL_FILENAME);
    let status = root.join(format!(".codeischeap-proxy-helper-{disconnect}.status"));
    let socket = env::temp_dir().join(format!(
        "codeischeap-proxy-helper-{}-{disconnect}.sock",
        std::process::id()
    ));
    let _ = fs::remove_file(&socket);
    let backend = FileProxyBackend::new(&state);
    let original = ProxySettings::AutoConfig {
        url: "https://config.example.test/proxy.pac".to_owned(),
    };
    let desired = ProxySettings::Manual {
        http_proxy: "http://127.0.0.1:43125".to_owned(),
        https_proxy: "http://127.0.0.1:43125".to_owned(),
        bypass: vec!["localhost".to_owned()],
    };
    backend.apply(&original).expect("seed PAC state");
    let owner_pid = std::process::id();
    let owner_uid = fs::metadata(&root).expect("root metadata").uid();
    let server_backend = backend.clone();
    let server_journal = journal.clone();
    let server_status = status.clone();
    let server_socket = socket.clone();
    let server = thread::spawn(move || {
        run_macos_proxy_helper_session(
            server_backend,
            desired,
            server_journal,
            server_status,
            server_socket,
            owner_pid,
            owner_uid,
            env!("CARGO_BIN_EXE_proxy-watchdog"),
        )
    });

    let session =
        MacOsPrivilegedProxySession::connect(&status, &socket, owner_uid, Duration::from_secs(15))
            .expect("owner must attach");
    assert_ne!(
        backend.snapshot().expect("proxy snapshot"),
        ProxySnapshot::File {
            settings: original.clone(),
        }
    );
    if disconnect {
        drop(session);
    } else {
        session.restore().expect("helper restore command");
    }
    server
        .join()
        .expect("helper thread must join")
        .expect("helper session must finish");
    assert_eq!(
        backend.snapshot().expect("restored proxy snapshot"),
        ProxySnapshot::File { settings: original }
    );
    assert!(!journal.exists());
    assert!(!status.exists());
    assert!(!socket.exists());
    fs::remove_dir_all(root).expect("test directory cleanup");
}

fn test_directory(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "codeischeap-macos-helper-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("test directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private permissions");
    path
}
