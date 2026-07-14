use std::env;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use codeischeap_proxy_recovery::{FileProxyBackend, ProxySession, ProxySettings};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some("hold".as_ref()) {
        return Err("usage: proxy-recovery-spike hold <state> <journal> <ready> <watchdog>".into());
    }
    let state = next_path(&mut arguments, "state")?;
    let journal = next_path(&mut arguments, "journal")?;
    let ready = next_path(&mut arguments, "ready")?;
    let watchdog = next_path(&mut arguments, "watchdog")?;
    if arguments.next().is_some() {
        return Err("unexpected proxy-recovery-spike argument".into());
    }

    let desired = ProxySettings::Manual {
        http_proxy: "http://127.0.0.1:3210".to_owned(),
        https_proxy: "http://127.0.0.1:3210".to_owned(),
        bypass: vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
    };
    let _session = ProxySession::begin(FileProxyBackend::new(state), desired, journal, watchdog)?;
    fs::write(ready, b"ready\n")?;
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn next_path(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing {name} path").into())
}
